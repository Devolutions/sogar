use std::{
    collections::HashMap,
    fs, io,
    io::{Error, ErrorKind, Write},
    path::{Path, PathBuf},
};

use regex::Regex;
use reqwest::{
    header::ToStrError,
    header::{ACCEPT, CONTENT_LENGTH, CONTENT_TYPE, LOCATION},
    Body, Client, Response,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;
use url::{ParseError, Url};

use crate::config::Settings;
use futures::StreamExt;
use slog_scope::{debug, error, info};
use tempfile::NamedTempFile;
use tokio::{fs::File, io::AsyncWriteExt};

#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(rename_all = "camelCase")]
pub struct Layer {
    pub media_type: String,
    pub digest: String,
    pub size: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub annotations: Option<HashMap<String, String>>,
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

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct BlobDigest {
    pub digest_type: String,
    pub value: String,
}

pub struct FileInfo {
    pub path: PathBuf,
    pub layer: Layer,
}

struct SogarCache {
    pub path: PathBuf,
    pub blob_path: PathBuf,
    pub manifest_path: PathBuf,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct AccessToken {
    pub client_id: String,
    pub grant_type: String,
    pub username: String,
    pub password: String,
    pub scope: String,
    pub service: String,
}

#[derive(Debug, Error)]
pub enum SogarError {
    #[error(transparent)]
    RequestError(#[from] reqwest::Error),
    #[error(transparent)]
    IoError(#[from] std::io::Error),
    #[error(transparent)]
    StrError(#[from] ToStrError),
    #[error(transparent)]
    ParseError(#[from] ParseError),
}

const PUT: &str = "Put";
const POST: &str = "Post";

const OCTET_STREAM: &str = "application/octet-stream";
const IMAGE_TITLE: &str = "org.opencontainers.image.title";

pub type SogarResult<T> = Result<T, SogarError>;

pub async fn export_sogar_file_artifact(settings: &Settings) -> SogarResult<()> {
    slog_scope::info!("settings are: {:?}", settings);
    let export = settings.command_data.clone();

    let access_token = get_access_token(&settings).await?;
    if let Some(reference) = parse_namespace(export.reference.clone()) {
        let mut layers = Vec::new();
        for filepath in &export.filepath {
            let push_file_path = Path::new(filepath.as_str());

            let annotations_map = create_annotation_for_filename(push_file_path);

            let push_data = read_file_data(push_file_path, export.media_type.clone(), Some(annotations_map))?;
            layers.push(push_data.layer.clone());
            export_sogar_blob(&settings, access_token.clone(), reference.clone(), push_data).await?;
        }

        let config_file = NamedTempFile::new()?;
        let config_data = create_config(config_file.path())?;

        let manifest_file = NamedTempFile::new()?;
        let manifest = Manifest {
            schema_version: 2,
            config: config_data.layer.clone(),
            layers,
        };

        let manifest_file_info = create_file_info(manifest, manifest_file.path())?;

        export_sogar_blob(&settings, access_token.clone(), reference.clone(), config_data).await?;

        export_sogar_manifest(&settings, access_token, reference, manifest_file_info).await?;
    }

    Ok(())
}

pub async fn import_sogar_file_artifact(settings: &Settings) -> SogarResult<()> {
    slog_scope::info!("settings are: {:?}", settings);
    let import = settings.command_data.clone();
    let access_token = get_access_token(&settings).await?;

    let sogar_cache = create_sogar_cache(settings.registry_cache.clone()).await?;

    if let Some(reference) = parse_namespace(import.reference.clone()) {
        let manifest = get_sogar_manifest(&settings, access_token.clone(), reference.clone(), &sogar_cache).await?;
        let out_file_path = import.filepath.clone();
        if out_file_path.is_empty() {
            return Err(str_to_sogar_error("The paths are empty!"));
        }

        save_sogar_blob(
            &settings,
            access_token.clone(),
            reference.clone(),
            manifest.config.clone(),
            &sogar_cache,
        )
        .await?;

        let mut blob_path = PathBuf::new();
        for (count, blob) in manifest.layers.iter().enumerate() {
            let from_path = save_sogar_blob(
                &settings,
                access_token.clone(),
                reference.clone(),
                blob.clone(),
                &sogar_cache,
            )
            .await?;

            if count < out_file_path.len() {
                blob_path = PathBuf::from(out_file_path.get(count).unwrap_or(&"".to_string()));
            }

            let new_path_buf = if blob_path.is_dir() {
                let mut path_buf = create_file_name_from_layer(&blob, blob_path.as_path());
                if path_buf.exists() {
                    path_buf = update_file_name(path_buf.as_path(), count + 1);
                }
                path_buf
            } else if blob_path.exists() {
                update_file_name(blob_path.as_path(), count + 1)
            } else {
                PathBuf::from(blob_path.to_str().unwrap_or_default())
            };

            fs::copy(from_path, new_path_buf)?;
        }
    }

    Ok(())
}

async fn create_sogar_cache(path: Option<String>) -> SogarResult<SogarCache> {
    let path_buff = match path {
        Some(cache_dir) => PathBuf::from(cache_dir),
        None => {
            let home_path = dirs_next::home_dir().unwrap_or_default();
            home_path.join(".sogar")
        }
    };

    let cache = SogarCache {
        blob_path: path_buff.join("blobs"),
        manifest_path: path_buff.join("manifests"),
        path: path_buff,
    };

    if !cache.path.exists() {
        fs::create_dir_all(cache.path.as_path())?
    }

    if !cache.blob_path.exists() {
        fs::create_dir_all(cache.blob_path.as_path())?
    }

    if !cache.manifest_path.exists() {
        fs::create_dir_all(cache.manifest_path.as_path())?
    }

    Ok(cache)
}

pub fn create_config(file_path: &Path) -> io::Result<FileInfo> {
    read_file_data(
        file_path,
        String::from("application/vnd.oci.image.config.v1+json"),
        None,
    )
}

fn create_file_name_from_layer(layer: &Layer, path: &Path) -> PathBuf {
    let digest_part_option = parse_digest(layer.digest.clone());
    let name = match &layer.annotations {
        Some(annotations) if !annotations.is_empty() && annotations.contains_key(IMAGE_TITLE) => {
            annotations.get(IMAGE_TITLE).unwrap_or(&"".to_string()).to_string()
        }
        _ => digest_part_option.map_or("".to_string(), |digest_part| digest_part.value),
    };

    path.join(name)
}

fn update_file_name(path: &Path, index: usize) -> PathBuf {
    let old_path = path.to_str().unwrap_or_default();
    let old_name = path.file_stem().unwrap_or_default().to_str().unwrap_or_default();
    let new_path = old_path.replace(old_name, format!("{}-{}", old_name, index).as_str());
    let mut new_path_buff = PathBuf::from(new_path);

    let mut update_index = 1;
    while new_path_buff.exists() {
        new_path_buff = update_file_name(path, index + update_index);
        update_index += 1;
    }

    new_path_buff
}

pub fn create_file_info(manifest: Manifest, file_path: &Path) -> io::Result<FileInfo> {
    use std::fs::File;
    let manifest_json = ::serde_json::to_string(&manifest)?;
    let manifest_bytes = manifest_json.as_bytes();

    let mut manifest_file = File::create(file_path)?;
    manifest_file.write_all(manifest_bytes)?;

    let path = PathBuf::from(file_path.to_str().unwrap_or_default().to_string());

    Ok(FileInfo {
        path,
        layer: Layer {
            media_type: String::from("application/vnd.oci.image.manifest.v1+json"),
            digest: String::new(),
            size: manifest_bytes.len() as u64,
            annotations: None,
        },
    })
}

pub fn read_file_data(
    file_path: &Path,
    media_type: String,
    annotations: Option<HashMap<String, String>>,
) -> io::Result<FileInfo> {
    use std::fs::File;
    let mut file = File::open(file_path)?;
    let file_size = file.metadata()?.len();

    let mut hasher = Sha256::new();

    io::copy(&mut file, &mut hasher)?;

    let artifact_digest_hash_type = "sha256";
    let artifact_digest_value = format!("{:x}", hasher.result()).to_lowercase();
    let artifact_digest = format!("{}:{}", artifact_digest_hash_type, artifact_digest_value);

    let layer = Layer {
        media_type,
        digest: artifact_digest,
        size: file_size,
        annotations,
    };

    let path = PathBuf::from(file_path.to_str().unwrap_or_default().to_string());

    Ok(FileInfo { path, layer })
}

async fn get_access_token(settings: &Settings) -> SogarResult<String> {
    if let Some(reference) = parse_namespace(settings.command_data.reference.clone()) {
        let scope = format!(
            "repository:{}/{}:pull repository:{}/{}:pull,push",
            reference.repository, reference.name, reference.repository, reference.name
        );

        let service = Url::parse(settings.registry_url.clone().as_str())?
            .host_str()
            .unwrap()
            .to_string();

        let token_data = AccessToken {
            client_id: String::from("sogar"),
            grant_type: String::from("password"),
            username: settings.username.clone(),
            password: settings.password.clone(),
            scope,
            service,
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
) -> SogarResult<()> {
    let client = Client::new();

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
        .header(ACCEPT, file_info.layer.media_type.clone())
        .send()
        .await?;

    if head_response.status() == 200 {
        info!(
            "Blob {} already found in registry, skipping push",
            file_info.layer.digest
        );
        return Ok(());
    }

    let post_url = format!(
        "{}/v2/{}/{}/blobs/uploads/",
        settings.registry_url.clone(),
        reference.repository.clone(),
        reference.name.clone()
    );

    let post_response = client
        .post(post_url.as_str())
        .bearer_auth(access_token.clone())
        .header(CONTENT_LENGTH, 0_u64)
        .header(CONTENT_TYPE, OCTET_STREAM)
        .send()
        .await?;

    let post_response = handle_response(post_response, POST, post_url.as_str())?;

    if post_response.headers().contains_key(LOCATION) {
        let location_header = post_response.headers().get(LOCATION);

        if location_header.is_none() {
            return Err(str_to_sogar_error("Location header is empty"));
        }

        let location = location_header.unwrap().to_str()?;
        let digest_separator = if location.contains('?') { "&" } else { "?" };

        let put_url = format!(
            "{}{}{}digest={}",
            settings.registry_url.clone(),
            location,
            digest_separator,
            file_info.layer.digest.clone()
        );

        let file = File::open(&file_info.path).await?;
        let body = file_to_body(file);
        let put_response = client
            .put(put_url.as_str())
            .bearer_auth(access_token)
            .header(CONTENT_LENGTH, file_info.layer.size)
            .header(CONTENT_TYPE, OCTET_STREAM)
            .body(body)
            .send()
            .await?;

        handle_response(put_response, PUT, put_url.as_str())?;
    }

    Ok(())
}

fn file_to_body(file: File) -> Body {
    use tokio_util::codec::{BytesCodec, FramedRead};

    let stream = FramedRead::new(file, BytesCodec::new());
    Body::wrap_stream(stream)
}

async fn save_sogar_blob(
    settings: &Settings,
    access_token: String,
    reference: Reference,
    layer: Layer,
    sogar_cache: &SogarCache,
) -> SogarResult<PathBuf> {
    let client = Client::new();
    let blob_digest = parse_digest(layer.digest.clone());
    if blob_digest.is_none() {
        return Err(str_to_sogar_error(
            format!("Failed to parse digest {:?}", blob_digest).as_str(),
        ));
    }

    let blob_digest = blob_digest.unwrap();

    let path = sogar_cache.blob_path.join(blob_digest.digest_type.clone());
    if !path.exists() {
        fs::create_dir_all(path.as_path())?
    }

    let output_blob = path.join(blob_digest.value.clone());
    if output_blob.exists() {
        info!("Blob {} already found in local cache, skipping pull", blob_digest.value);
        return Ok(output_blob);
    }

    let accept_list = format!("{},{}", layer.media_type.as_str(), "*/*");

    let get_url = format!(
        "{}/v2/{}/{}/blobs/{}",
        settings.registry_url.clone(),
        reference.repository.clone(),
        reference.name.clone(),
        layer.digest.clone()
    );

    let get_response = client
        .get(get_url.as_str())
        .bearer_auth(access_token.clone())
        .header(ACCEPT, accept_list)
        .send()
        .await?;

    let mut file = File::create(output_blob.as_path()).await?;

    let mut bytes_stream = get_response.bytes_stream();
    while let Some(item) = bytes_stream.next().await {
        file.write_all(&item.unwrap()).await?;
    }

    Ok(output_blob)
}

async fn export_sogar_manifest(
    settings: &Settings,
    access_token: String,
    reference: Reference,
    file_info: FileInfo,
) -> SogarResult<()> {
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

    let result = client
        .head(head_url.as_str())
        .bearer_auth(access_token.clone())
        .header(ACCEPT, media_type)
        .send()
        .await;

    debug!("head request for manifest {:?}", result);

    let put_url = format!(
        "{}/v2/{}/{}/manifests/{}",
        settings.registry_url.clone(),
        reference.repository.clone(),
        reference.name.clone(),
        tag.clone()
    );

    let file = File::open(&file_info.path).await?;
    let body = file_to_body(file);
    let put_response = client
        .put(put_url.as_str())
        .bearer_auth(access_token)
        .header(CONTENT_TYPE, media_type)
        .header(CONTENT_LENGTH, file_info.layer.size)
        .body(body)
        .send()
        .await?;

    handle_response(put_response, PUT, put_url.as_str())?;

    Ok(())
}

async fn get_sogar_manifest(
    settings: &Settings,
    access_token: String,
    reference: Reference,
    sogar_cache: &SogarCache,
) -> SogarResult<Manifest> {
    let client = Client::new();
    let accept_list = format!(
        "{},{},{},{},{}",
        "application/vnd.docker.distribution.manifest.v2+json",
        "application/vnd.docker.distribution.manifest.list.v2+json",
        "application/vnd.oci.image.manifest.v1+json",
        "application/vnd.oci.image.index.v1+json",
        "*/*"
    );

    let tag = match reference.tag {
        Some(tag) => tag,
        None => String::from("null"),
    };

    let get_url = format!(
        "{}/v2/{}/{}/manifests/{}",
        settings.registry_url.clone(),
        reference.repository.clone(),
        reference.name.clone(),
        tag.clone()
    );

    let get_response = client
        .get(get_url.as_str())
        .bearer_auth(access_token.clone())
        .header(ACCEPT, accept_list)
        .send()
        .await?
        .json::<Manifest>()
        .await?;

    let manifest_path = sogar_cache
        .manifest_path
        .join(reference.repository)
        .join(reference.name);

    if !manifest_path.exists() {
        fs::create_dir_all(manifest_path.as_path())?
    }

    let mut file = File::create(manifest_path.join(tag).as_path()).await?;
    file.write_all(serde_json::to_string(&get_response).unwrap_or_default().as_bytes())
        .await?;

    Ok(get_response)
}

fn handle_response(response: Response, request_type: &str, url: &str) -> SogarResult<Response> {
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
    SogarError::IoError(Error::new(ErrorKind::InvalidData, error))
}

fn parse_namespace(reference: String) -> Option<Reference> {
    let reference_tag = Regex::new(r"(.*)/(.*):(.*)").unwrap();
    let reference_no_tag = Regex::new(r"(.*)/(.*)").unwrap();

    let split_value = if reference_tag.is_match(reference.as_str()) {
        Some(vec!['/', ':'])
    } else if reference_no_tag.is_match(reference.as_str()) {
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
        let items = split.into_iter().map(ToString::to_string).collect::<Vec<String>>();

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

    None
}

pub fn parse_digest(blobs_digest: String) -> Option<BlobDigest> {
    let digest_type = 0;
    let value = 1;
    let max_items_size = 2;

    let split = blobs_digest.split(':');
    let items = split.into_iter().map(ToString::to_string).collect::<Vec<String>>();

    if items.len() != max_items_size {
        None
    } else {
        Some(BlobDigest {
            digest_type: items[digest_type].clone(),
            value: items[value].clone(),
        })
    }
}

pub fn create_annotation_for_filename(push_file_path: &Path) -> HashMap<String, String> {
    let file_name = push_file_path
        .file_stem()
        .unwrap_or_default()
        .to_str()
        .unwrap_or_default()
        .to_string();

    let mut annotations_map = HashMap::new();
    annotations_map.insert(String::from(IMAGE_TITLE), file_name);
    annotations_map
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_reference_with_tag() {
        let reference = parse_namespace(String::from("videos/demo:latest"));
        assert_eq!(reference.is_some(), true);
        let reference = reference.unwrap();
        assert_eq!(reference.repository, String::from("videos"));
        assert_eq!(reference.name, String::from("demo"));
        assert_eq!(reference.tag.is_some(), true);
        assert_eq!(reference.tag.unwrap(), String::from("latest"));
    }

    #[test]
    fn test_reference_no_tag() {
        let reference = parse_namespace(String::from("videos/demo"));
        assert_eq!(reference.is_some(), true);
        let reference = reference.unwrap();
        assert_eq!(reference.repository, String::from("videos"));
        assert_eq!(reference.name, String::from("demo"));
        assert_eq!(reference.tag, None);
    }

    #[test]
    fn test_incorrect_reference() {
        let reference = parse_namespace(String::from("videos"));
        assert_eq!(reference.is_none(), true);
    }

    #[test]
    fn test_correct_digest() {
        let blob_digest = parse_digest(String::from(
            "sha256:0c01ac7e3eeaa94647da076b1c2ddbbab56831c55bea4abe47cf35ab2ced5da8",
        ));
        assert_eq!(blob_digest.is_some(), true);
        let blob_digest = blob_digest.unwrap();
        assert_eq!(blob_digest.digest_type, String::from("sha256"));
        assert_eq!(
            blob_digest.value,
            String::from("0c01ac7e3eeaa94647da076b1c2ddbbab56831c55bea4abe47cf35ab2ced5da8")
        );
    }

    #[test]
    fn test_incorrect_digest() {
        let blob_digest = parse_digest(String::from("sha256"));
        assert_eq!(blob_digest.is_none(), true);
    }

    #[test]
    fn create_file_name_from_layer_created_from_digest() {
        let hash = "0c01ac7e3eeaa94647da076b1c2ddbbab56831c55bea4abe47cf35ab2ced5da8";
        let path = Path::new("test");
        let layer = Layer {
            media_type: "".to_string(),
            digest: format!("sha256:{}", hash),
            size: 0,
            annotations: None,
        };

        let result = create_file_name_from_layer(&layer, path);
        assert_eq!(result, PathBuf::from(format!("test/{}", hash)));
    }

    #[test]
    fn create_file_name_from_layer_created_from_annotation() {
        let hash = "0c01ac7e3eeaa94647da076b1c2ddbbab56831c55bea4abe47cf35ab2ced5da8";
        let filename = String::from("file1");
        let mut annotations = HashMap::new();
        annotations.insert(String::from(IMAGE_TITLE), filename.clone());

        let path = Path::new("test");
        let layer = Layer {
            media_type: "".to_string(),
            digest: format!("sha256:{}", hash),
            size: 0,
            annotations: Some(annotations),
        };

        let result = create_file_name_from_layer(&layer, path);
        assert_eq!(result, PathBuf::from(format!("test/{}", filename)));
    }
}
