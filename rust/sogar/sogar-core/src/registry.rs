use crate::{parse_digest, Manifest};
use hyper::body::HttpBody;
use regex::Regex;
use saphir::hyper::body::Buf;
use saphir::prelude::*;
use serde::Deserialize;
use slog_scope::{debug, error};
use std::collections::HashMap;
use std::fs::create_dir_all;
use std::io;
use std::io::Write;
use std::path::Path;
use tokio_02::io::AsyncWriteExt;

const REPOSITORY: &str = "repository";
const IMAGE_NAME: &str = "image_name";
const DIGEST: &str = "digest";
const TAG: &str = "tag";
pub const ARTIFACTS_DIR: &str = "artifacts";
const ARTIFACTS_CONTENT: &str = "content.yaml";

pub const BLOB_PATH: &str = "/registry/v2/<repository>/<image_name>/blobs/<digest>";
pub const BLOB_GET_LOCATION_PATH: &str = "/registry/v2/<repository>/<image_name>/blobs/uploads";
pub const UPLOAD_BLOB_PATH: &str = "/registry/<repository>/<image_name>";
pub const MANIFEST_PATH: &str = "/registry/v2/<repository>/<image_name>/manifests/<tag>";

pub const BLOB_EXIST_ENDPOINT: &str = "is_blob_exist";
pub const BLOB_GET_LOCATION_ENDPOINT: &str = "get_blob_location";
pub const BLOB_UPLOAD_ENDPOINT: &str = "save_blob";
pub const BLOB_DOWNLOAD_ENDPOINT: &str = "get_blob";
pub const MANIFEST_EXIST_ENDPOINT: &str = "is_manifest_exist";
pub const MANIFEST_UPLOAD_ENDPOINT: &str = "save_manifest";
pub const MANIFEST_DOWNLOAD_ENDPOINT: &str = "get_manifest";

const CONTENT_TYPE_HEADER: &str = "content-type";
const ACCEPT_HEADER: &str = "accept";

pub struct SogarCustomResponse {
    headers: HashMap<String, String>,
    status: StatusCode,
    file: Option<File>,
}

impl SogarCustomResponse {
    pub fn new(status: StatusCode) -> Self {
        SogarCustomResponse {
            headers: HashMap::new(),
            status,
            file: None,
        }
    }

    pub fn header(&mut self, key: &str, value: &str) {
        self.headers.insert(key.to_string(), value.to_string());
    }

    pub fn file(&mut self, file: File) {
        self.file = Some(file);
    }
}

impl Responder for SogarCustomResponse {
    fn respond_with_builder(self, builder: Builder, _ctx: &HttpContext) -> Builder {
        let mut builder_copy = builder;
        for (key, val) in self.headers {
            builder_copy = builder_copy.header(&key, val);
        }

        builder_copy = builder_copy.status(self.status);

        if let Some(file) = self.file {
            builder_copy = builder_copy.file(file);
        }

        builder_copy
    }
}

pub struct SogarController {
    _priv: (),
}

impl SogarController {
    pub fn new(registry: &str, image_name: &str) -> Self {
        use std::fs::File;

        let path = Path::new(registry).join(image_name);
        if let Err(e) = create_dir_all(path.join(ARTIFACTS_DIR)) {
            error!("Failed to create registry! {}", e);
        }

        let content = path.join(ARTIFACTS_CONTENT);
        if !content.exists() {
            match File::create(path.join(ARTIFACTS_CONTENT)) {
                Ok(mut file) => {
                    if let Err(e) = writeln!(file, "artifacts:") {
                        error!("Couldn't write to file: {}", e);
                    }
                }
                Err(e) => {
                    error!("Failed to create file with artifacts content! {}", e);
                }
            }
        }

        Self { _priv: () }
    }
}

#[controller(name = "registry")]
impl SogarController {
    #[head("/v2/<repository>/<image_name>/blobs/<digest>")]
    async fn is_blob_exist(&self, req: Request) -> impl Responder {
        debug!("Head request for blob");
        let map = req.captures();

        if let (Some(repository), Some(image_name), Some(digest)) =
            (map.get(REPOSITORY), map.get(IMAGE_NAME), map.get(DIGEST))
        {
            if let Some(digest) = parse_digest(digest.to_string()) {
                let path = Path::new(repository)
                    .join(image_name)
                    .join(ARTIFACTS_DIR)
                    .join(&digest.digest_type)
                    .join(&digest.value);

                if path.exists() {
                    let mut response = SogarCustomResponse::new(StatusCode::OK);
                    response.header(
                        "Docker-Content-Digest",
                        format!("{}:{}", digest.digest_type, digest.value).as_str(),
                    );
                    return response;
                }
            }
        }

        SogarCustomResponse::new(StatusCode::NOT_FOUND)
    }

    #[post("/v2/<repository>/<image_name>/blobs/uploads/")]
    async fn get_blob_location(&self, req: Request) -> impl Responder {
        debug!("Post request for blob");
        let map = req.captures();

        if let (Some(repository), Some(image_name)) = (map.get(REPOSITORY), map.get(IMAGE_NAME)) {
            let path = Path::new(repository).join(image_name);
            if path.exists() {
                let mut response = SogarCustomResponse::new(StatusCode::ACCEPTED);
                response.header("Location", format!("/{}/{}", repository, image_name).as_str());
                return response;
            }
        }

        SogarCustomResponse::new(StatusCode::NOT_FOUND)
    }

    // Full url example: /<repository>/<image_name>&digest=<digest>
    #[put("/<repository>/<image_name>")]
    async fn save_blob(&self, mut req: Request) -> impl Responder {
        debug!("Put request for blob");

        let body: hyper::Body = req.body_mut().take().into();

        let digest = parse_digest_uri(req.uri());
        let map = req.captures();

        if let (Some(repository), Some(image_name), Some(digest)) = (map.get(REPOSITORY), map.get(IMAGE_NAME), digest) {
            let path = Path::new(repository).join(image_name).join(ARTIFACTS_DIR);
            if path.exists() {
                if let Some(blob_digest) = parse_digest(digest.clone()) {
                    let path = path.join(blob_digest.digest_type.as_str());
                    if !path.exists() {
                        if let Err(e) = create_dir_all(path.as_path()) {
                            error!("Failed to create directory for saving blob {}", e);
                            return SogarCustomResponse::new(StatusCode::BAD_REQUEST);
                        }
                    }

                    let path = path.join(blob_digest.value.as_str());

                    if let Err(error_response) = remove_file_if_exists(path.as_path()) {
                        return error_response;
                    }

                    if let Err(e) = write_body_to_file(body, path.as_path()).await {
                        error!("Failed to write data to the file {}", e);
                        return SogarCustomResponse::new(StatusCode::BAD_REQUEST);
                    }

                    let mut response = SogarCustomResponse::new(StatusCode::CREATED);
                    response.header(
                        "Location",
                        format!("/v2/{}/{}/blobs/{}", repository, image_name, digest).as_str(),
                    );

                    return response;
                }
            }
        }

        SogarCustomResponse::new(StatusCode::NOT_FOUND)
    }

    #[head("/v2/<repository>/<image_name>/manifests/<tag>")]
    async fn is_manifest_exist(&self, req: Request) -> (StatusCode, ()) {
        debug!("Head request for manifest");

        let map = req.captures();

        if let (Some(repository), Some(image_name), Some(tag)) =
            (map.get(REPOSITORY), map.get(IMAGE_NAME), map.get(TAG))
        {
            let path = Path::new(repository).join(image_name).join(ARTIFACTS_DIR).join(tag);
            if path.exists() {
                return (StatusCode::OK, ());
            }
        }

        (StatusCode::NOT_FOUND, ())
    }

    #[put("/v2/<repository>/<image_name>/manifests/<tag>")]
    async fn save_manifest(&self, mut req: Request) -> impl Responder {
        debug!("Put request for manifest");
        let body: hyper::Body = req.body_mut().take().into();

        let map = req.captures();
        let headers = req.headers();

        if let (Some(repository), Some(image_name), Some(tag)) =
            (map.get(REPOSITORY), map.get(IMAGE_NAME), map.get(TAG))
        {
            let image_path = Path::new(repository).join(image_name);
            let path = image_path.join(ARTIFACTS_DIR);
            if path.exists() {
                let path = path.join(tag);

                if let Err(error_response) = remove_file_if_exists(path.as_path()) {
                    return error_response;
                }

                if let Err(e) = write_body_to_file(body, path.as_path()).await {
                    error!("Failed to write data to the file {}", e);
                    return SogarCustomResponse::new(StatusCode::BAD_REQUEST);
                }

                let mut manifest_mime_type = None;
                if headers.contains_key(CONTENT_TYPE_HEADER) {
                    manifest_mime_type = headers
                        .get(CONTENT_TYPE_HEADER)
                        .and_then(|header| header.to_str().map_or(None, |result| Some(result.to_string())));
                }

                add_artifacts_info(tag.clone(), manifest_mime_type, image_path.as_path());

                let mut response = SogarCustomResponse::new(StatusCode::CREATED);
                response.header(
                    "Location",
                    format!("/v2/{}/{}/manifests/{}", repository, image_name, tag).as_str(),
                );

                return response;
            }
        }

        SogarCustomResponse::new(StatusCode::BAD_REQUEST)
    }

    #[get("/v2/<repository>/<image_name>/manifests/<tag>")]
    async fn get_manifest(&self, req: Request) -> (StatusCode, Option<File>) {
        debug!("Get request for manifest");
        let map = req.captures();
        let headers = req.headers();

        if let (Some(repository), Some(image_name), Some(tag)) =
            (map.get(REPOSITORY), map.get(IMAGE_NAME), map.get(TAG))
        {
            let image_path = Path::new(repository).join(image_name);
            let path = image_path.join(ARTIFACTS_DIR).join(tag);
            let content_type = read_artifact_info(tag.to_string(), image_path.as_path());

            if headers.contains_key(ACCEPT_HEADER) {
                if let (Some(accept_value), Some(content_type)) = (
                    headers.get(ACCEPT_HEADER).and_then(|header| header.to_str().ok()),
                    content_type,
                ) {
                    if accept_value.contains(&content_type) || accept_value.contains("*/*") {
                        return get_file_if_exists(path.as_path()).await;
                    }
                }
            } else {
                return get_file_if_exists(path.as_path()).await;
            }
        }

        (StatusCode::NOT_FOUND, None)
    }

    #[get("/v2/<repository>/<image_name>/blobs/<digest>")]
    async fn get_blob(&self, req: Request) -> impl Responder {
        debug!("Get request for blob");

        let map = req.captures();

        if let (Some(repository), Some(image_name), Some(digest)) =
            (map.get(REPOSITORY), map.get(IMAGE_NAME), map.get(DIGEST))
        {
            if let Some(digest) = parse_digest(digest.to_string()) {
                let image_path = Path::new(repository).join(image_name);
                let path = image_path
                    .join(ARTIFACTS_DIR)
                    .join(&digest.digest_type)
                    .join(&digest.value);
                let (status_code, file_result) = get_file_if_exists(path.as_path()).await;

                if let Some(file) = file_result {
                    let content_type = read_artifact_info(digest.value, image_path.as_path());

                    let mut response = SogarCustomResponse::new(status_code);
                    response.file(file);

                    if let Some(content_type) = content_type {
                        response.header(CONTENT_TYPE_HEADER, content_type.as_str());
                    }

                    return response;
                }
            }
        }

        SogarCustomResponse::new(StatusCode::NOT_FOUND)
    }
}

async fn write_body_to_file(mut body: hyper::Body, path: &Path) -> io::Result<()> {
    use tokio_02::fs::File;

    let mut file = File::create(path).await?;

    while let Some(chunk_res) = body.data().await {
        match chunk_res {
            Ok(chunk) => {
                debug!("Got a chunk [len = {}]", chunk.len());
                file.write_all(chunk.bytes()).await?
            }

            Err(e) => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("Failed to read chunk! Error is {}", e),
                ));
            }
        }
    }

    file.flush().await?;

    Ok(())
}

fn parse_digest_uri(uri: &Uri) -> Option<String> {
    if let Some(digest_uri) = uri.query() {
        let digest_index = 1;
        let digest_re = Regex::new(r"(.*)=(.*)").unwrap();

        if digest_re.is_match(digest_uri) {
            let split = digest_uri.split('=');
            let result = split.into_iter().map(ToString::to_string).collect::<Vec<String>>();
            return Some(result[digest_index].clone());
        }
    }

    None
}

fn remove_file_if_exists(path: &Path) -> std::result::Result<(), SogarCustomResponse> {
    if path.exists() {
        if let Err(e) = std::fs::remove_file(path) {
            error!("Failed to delete existed file {:?} with error {}", path, e);
            return Err(SogarCustomResponse::new(StatusCode::BAD_REQUEST));
        }
    }

    Ok(())
}

async fn get_file_if_exists(path: &Path) -> (StatusCode, Option<File>) {
    if path.exists() && path.to_str().is_some() {
        if let Ok(file) = File::open(path.to_str().unwrap()).await {
            return (StatusCode::OK, Some(file));
        }
    }

    (StatusCode::NOT_FOUND, None)
}

pub fn add_artifacts_info(filename: String, manifest_mime: Option<String>, image_path: &Path) {
    use std::fs::{File, OpenOptions};

    let content_path = image_path.join(ARTIFACTS_CONTENT);
    let filepath = image_path.join(ARTIFACTS_DIR).join(&filename);

    let file = File::open(filepath);

    if let Ok(file) = file {
        let json = serde_json::from_reader(file);
        if let Err(e) = json {
            error!("Failed to convert manifest data to json with error: {}", e);
            return;
        }

        let artifacts_content_file = OpenOptions::new().write(true).append(true).open(content_path);

        let manifest: Manifest = json.unwrap();

        if let Ok(mut file) = artifacts_content_file {
            for layer in manifest.layers {
                if let Some(digest) = parse_digest(layer.digest.clone()) {
                    if let Err(e) = writeln!(file, "{}", format!("  {}: {}", digest.value, layer.media_type)) {
                        error!("Couldn't write to file: {}", e);
                    }
                }
            }

            if let Some(manifest_mime) = manifest_mime {
                if let Err(e) = writeln!(file, "{}", format!("  {}: {}", filename, manifest_mime)) {
                    error!("Couldn't write to file: {}", e);
                }
            }
        }
    }
}

fn read_artifact_info(digest_value: String, image_path: &Path) -> Option<String> {
    use std::fs::File;

    let content_path = image_path.join(ARTIFACTS_CONTENT);
    match File::open(&content_path) {
        Ok(file) => {
            #[derive(Deserialize)]
            struct ArtifactsData {
                artifacts: HashMap<String, String>,
            }

            let yaml = serde_yaml::from_reader(file);
            if let Err(e) = yaml {
                error!("Failed to convert manifest data to yaml with error: {}", e);
                return None;
            }

            let blobs_data: ArtifactsData = yaml.unwrap();
            if blobs_data.artifacts.contains_key(digest_value.as_str()) {
                return blobs_data
                    .artifacts
                    .get(digest_value.as_str())
                    .map(|mime_type| mime_type.to_string());
            }
        }
        Err(e) => {
            error!("Content file ({}) can't be opened: {}", content_path.display(), e);
        }
    }

    None
}
