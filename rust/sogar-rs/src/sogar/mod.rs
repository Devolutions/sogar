use std::{
    fs::File,
    io::{Error, ErrorKind, Read},
    path::Path,
};

use regex::Regex;
use reqwest::{
    header::ToStrError,
    header::{ACCEPT, CONTENT_LENGTH, CONTENT_TYPE, LOCATION},
    Client, Response,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;
use url::{ParseError, Url};

use sogar_config::Settings;
use tempfile::NamedTempFile;

pub mod sogar_config;

#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(rename_all = "camelCase")]
pub struct Layer {
    pub media_type: String,
    pub digest: String,
    pub size: u64,
}

#[derive(Serialize, Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
pub struct Manifest {
    pub schema_version: u32,
    pub config: Layer,
    pub layers: Vec<Layer>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct Reference {
    pub repository: String,
    pub name: String,
    pub tag: Option<String>,
}

pub struct FileInfo {
    pub data: Vec<u8>,
    pub layer: Layer,
}

#[derive(Debug, Error)]
pub enum SogarError {
    #[error(transparent)]
    RequestError(#[from] reqwest::Error),
    #[error(transparent)]
    StdError(#[from] std::io::Error),
    #[error(transparent)]
    StrError(#[from] ToStrError),
    #[error(transparent)]
    ParseError(#[from] ParseError),
}

const HEAD: &str = "Head";
const PUT: &str = "Put";
const POST: &str = "Post";

const OCTET_STREAM: &str = "application/octet-stream";

pub async fn export_sogar_file_artifact(settings: &Settings) -> Result<(), SogarError> {
    if let Some(export) = &settings.export {
        let push_data = read_file_data(Path::new(export.filepath.as_str()), export.media_type.clone()).await?;

        let mut layers = Vec::new();
        layers.push(push_data.layer.clone());

        let config_file = NamedTempFile::new()?;
        let config_data = read_file_data(config_file.path(), String::from("application/json")).await?;

        let manifest = Manifest {
            schema_version: 2,
            config: config_data.layer.clone(),
            layers,
        };

        let manifest_file = create_manifest(&manifest).await?;

        let access_token = get_access_token(&settings).await?;
        if let Some(reference) = parse_namespace(&settings) {
            export_sogar_blob(&settings, access_token.clone(), reference.clone(), push_data).await?;

            export_sogar_blob(&settings, access_token.clone(), reference.clone(), config_data).await?;

            export_sogar_manifest(&settings, access_token, reference, manifest_file).await?;
        }
    }
    Ok(())
}

async fn create_manifest(manifest: &Manifest) -> Result<FileInfo, std::io::Error> {
    let manifest_json = ::serde_json::to_string(&manifest)?;
    let manifest_bytes = manifest_json.as_bytes();

    Ok(FileInfo {
        data: manifest_bytes.to_vec(),
        layer: Layer {
            media_type: String::from("application/vnd.oci.image.manifest.v1+json"),
            digest: String::new(),
            size: manifest_bytes.len() as u64,
        },
    })
}

async fn read_file_data(file_path: &Path, media_type: String) -> Result<FileInfo, std::io::Error> {
    let mut file = File::open(file_path)?;
    let file_size = file.metadata()?.len();

    let mut hasher = Sha256::new();
    let mut data = Vec::new();

    file.read_to_end(&mut data)?;
    hasher.input(data.as_slice());

    let artifact_digest_hash_type = "sha256";
    let artifact_digest_value = format!("{:x}", hasher.result()).to_lowercase();
    let artifact_digest = format!("{}:{}", artifact_digest_hash_type, artifact_digest_value);

    let layer = Layer {
        media_type,
        digest: artifact_digest,
        size: file_size,
    };

    Ok(FileInfo { data, layer })
}

async fn get_access_token(settings: &Settings) -> Result<String, SogarError> {
    #[derive(Serialize, Deserialize, Debug)]
    pub struct AccessToken {
        client_id: String,
        grant_type: String,
        username: String,
        password: String,
        scope: String,
        service: String,
    }

    if let Some(reference) = parse_namespace(settings) {
        let token_data = AccessToken {
            client_id: String::from("sogar"),
            grant_type: String::from("password"),
            username: settings.username.clone(),
            password: settings.password.clone(),
            scope: format!(
                "repository:{}/{}:pull repository:{}/{}:pull,push",
                reference.repository, reference.name, reference.repository, reference.name
            ),
            service: Url::parse(settings.registry_url.clone().as_str())?
                .host_str()
                .unwrap()
                .to_string(),
        };

        let client = Client::new();
        #[derive(Deserialize)]
        struct ResponseAccessToken {
            access_token: String,
        }

        let response = client
            .post(format!("{}/oauth2/token", settings.registry_url.clone()).as_str())
            .form(&token_data)
            .send()
            .await?
            .json::<ResponseAccessToken>()
            .await?;

        return Ok(response.access_token);
    }

    Err(str_to_sogar_error("Failed to parse reference"))
}

async fn export_sogar_blob(
    settings: &Settings,
    access_token: String,
    reference: Reference,
    file_info: FileInfo,
) -> Result<(), SogarError> {
    let client = Client::new();

    let export = settings.export.as_ref();
    if let None = export {
        return Err(str_to_sogar_error("Export struct is empty"));
    }

    let export = export.unwrap();

    let media_type = export.media_type.clone();

    let head_url = format!(
        "{}/v2/{}/{}/blobs/{}",
        settings.registry_url.clone(),
        reference.repository.clone(),
        reference.name.clone(),
        file_info.layer.digest.clone()
    );

    let head_response = client
        .head(head_url.as_str())
        .bearer_auth(access_token.clone())
        .header(ACCEPT, media_type)
        .send()
        .await?;

    handle_response(head_response, HEAD, head_url.as_str())?;

    let post_url = format!(
        "{}/v2/{}/{}/blobs/uploads/",
        settings.registry_url.clone(),
        reference.repository.clone(),
        reference.name.clone()
    );

    let post_response = client
        .post(post_url.as_str())
        .bearer_auth(access_token.clone())
        .header(CONTENT_LENGTH, 0 as u64)
        .header(CONTENT_TYPE, OCTET_STREAM)
        .send()
        .await?;

    let post_response = handle_response(post_response, POST, post_url.as_str())?;

    if post_response.headers().contains_key(LOCATION) {
        let location_header = post_response.headers().get(LOCATION);

        if let None = location_header {
            return Err(str_to_sogar_error("Location header is empty"));
        }

        let location = location_header.unwrap().to_str()?;

        let put_url = format!(
            "{}{}&digest={}",
            settings.registry_url.clone(),
            location,
            file_info.layer.digest.clone()
        );

        let put_response = client
            .put(put_url.as_str())
            .bearer_auth(access_token)
            .header(CONTENT_LENGTH, file_info.layer.size)
            .header(CONTENT_TYPE, OCTET_STREAM)
            .body(file_info.data)
            .send()
            .await?;

        handle_response(put_response, PUT, put_url.as_str())?;
    }
    Ok(())
}

async fn export_sogar_manifest(
    settings: &Settings,
    access_token: String,
    reference: Reference,
    file_info: FileInfo,
) -> Result<(), SogarError> {
    let client = Client::new();
    let media_type = file_info.layer.media_type.as_str();

    let tag = match reference.tag {
        Some(tag) => tag,
        None => String::from("null"),
    };

    let head_url = format!(
        "{}/v2/{}/{}/manifests/{}",
        settings.registry_url.clone(),
        reference.repository.clone(),
        reference.name.clone(),
        tag.clone()
    );
    let head_response = client
        .head(head_url.as_str())
        .bearer_auth(access_token.clone())
        .header(ACCEPT, media_type)
        .send()
        .await?;

    handle_response(head_response, HEAD, head_url.as_str())?;

    let put_url = format!(
        "{}/v2/{}/{}/manifests/{}",
        settings.registry_url.clone(),
        reference.repository.clone(),
        reference.name.clone(),
        tag.clone()
    );

    let put_response = client
        .put(put_url.as_str())
        .bearer_auth(access_token)
        .header(CONTENT_TYPE, media_type)
        .header(CONTENT_LENGTH, file_info.layer.size)
        .body(file_info.data)
        .send()
        .await?;

    handle_response(put_response, PUT, put_url.as_str())?;

    Ok(())
}

fn handle_response(response: Response, request_type: &str, url: &str) -> Result<Response, SogarError> {
    if !response.status().is_success() {
        Err(str_to_sogar_error(
            format!(
                "{} request to {} failed: {}",
                request_type,
                url,
                response.status().to_string()
            )
            .as_str(),
        ))
    } else {
        Ok(response)
    }
}

fn str_to_sogar_error(error: &str) -> SogarError {
    SogarError::StdError(Error::new(ErrorKind::InvalidData, error))
}

fn parse_namespace(settings: &Settings) -> Option<Reference> {
    if let Some(export) = &settings.export {
        let reference = export.reference.clone();
        let reference_tag = Regex::new(r"(.*)/(.*):(.*)").unwrap();
        let reference_no_tag = Regex::new(r"(.*)/(.*)").unwrap();

        let split_value = if reference_tag.is_match(export.reference.as_str()) {
            Some(vec!['/', ':'])
        } else if reference_no_tag.is_match(export.reference.as_str()) {
            Some(vec!['/'])
        } else {
            None
        };

        if let Some(value) = split_value {
            let repository_index = 0;
            let name_index = 1;
            let tag_index = 2;
            let max_items_size = 3;

            let split = reference.split(value.as_slice());
            let items = split.into_iter().map(|item| item.to_string()).collect::<Vec<String>>();

            let tag = if items.len() == max_items_size {
                Some(items[tag_index].clone())
            } else {
                None
            };
            return Some(Reference {
                repository: items[repository_index].clone(),
                name: items[name_index].clone(),
                tag,
            });
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use crate::r#mod::sogar_config::Export;

    use super::*;
    use crate::sogar::sogar_config::Export;

    #[test]
    fn test_reference_with_tag() {
        let settings = Settings {
            registry_url: String::new(),
            username: String::new(),
            password: String::new(),
            export: Some(Export {
                media_type: String::new(),
                reference: String::from("videos/demo:latest"),
                filepath: String::new(),
            }),
        };

        let reference = parse_namespace(&settings);
        assert_eq!(true, reference.is_some());
        let reference = reference.unwrap();
        assert_eq!(reference.repository, String::from("videos"));
        assert_eq!(reference.name, String::from("demo"));
        assert_eq!(reference.tag.is_some(), true);
        assert_eq!(reference.tag.unwrap(), String::from("latest"));
    }

    #[test]
    fn test_reference_no_tag() {
        let settings = Settings {
            registry_url: String::new(),
            username: String::new(),
            password: String::new(),
            export: Some(Export {
                media_type: String::new(),
                reference: String::from("videos/demo"),
                filepath: String::new(),
            }),
        };

        let reference = parse_namespace(&settings);
        assert_eq!(true, reference.is_some());
        let reference = reference.unwrap();
        assert_eq!(reference.repository, String::from("videos"));
        assert_eq!(reference.name, String::from("demo"));
        assert_eq!(reference.tag, None);
    }

    #[test]
    fn test_incorrect_reference() {
        let settings = Settings {
            registry_url: String::new(),
            username: String::new(),
            password: String::new(),
            export: Some(Export {
                media_type: String::new(),
                reference: String::from("videos"),
                filepath: String::new(),
            }),
        };

        let reference = parse_namespace(&settings);
        assert_eq!(true, reference.is_none());
    }
}
