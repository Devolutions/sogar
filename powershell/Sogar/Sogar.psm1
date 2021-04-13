
# https://github.com/opencontainers/distribution-spec/blob/main/spec.md

class SogarCache
{
    [string] $Path
    [string] $BlobPath
    [string] $ManifestPath

    SogarCache() { }
}

function New-SogarCache
{
    [CmdletBinding()]
    param(
        [string] $Path
    )

    $Cache = [SogarCache]::new()

    $HomePath = Resolve-Path "~"

    if ([string]::IsNullOrEmpty($Path)) {
        if ($Env:SOGAR_REGISTRY_CACHE) {
            $Path = $Env:SOGAR_REGISTRY_CACHE
        } else {
            $Path = Join-Path $HomePath ".sogar"
        }
    }

    $BlobPath = Join-Path $Path "blobs"
    $ManifestPath = Join-Path $Path "manifests"

    $Cache.Path = $Path
    $Cache.BlobPath = $BlobPath
    $Cache.ManifestPath = $ManifestPath

    New-Item -Path $Path -ItemType Directory -ErrorAction SilentlyContinue | Out-Null
    New-Item -Path $BlobPath -ItemType Directory -ErrorAction SilentlyContinue | Out-Null
    New-Item -Path $ManifestPath -ItemType Directory -ErrorAction SilentlyContinue | Out-Null

    $Cache
}

class SogarRegistry
{
    [string] $Url
    [string] $Username
    [string] $Password
    [string] $AccessToken
    [SogarCache] $Cache

    SogarRegistry() { }
}

function New-SogarRegistry
{
    [CmdletBinding()]
    param(
        [string] $Url,
        [string] $Username,
        [string] $Password,
        [SogarCache] $Cache
    )

    $Registry = [SogarRegistry]::new()
    
    if (-Not $Cache) {
        $Cache = New-SogarCache
    }

    $Registry.Cache = $Cache

    if ($Env:SOGAR_REGISTRY_URL) {
        $Registry.Url = $Env:SOGAR_REGISTRY_URL
    }

    if ($Env:SOGAR_REGISTRY_USERNAME) {
        $Registry.Username = $Env:SOGAR_REGISTRY_USERNAME
    }

    if ($Env:SOGAR_REGISTRY_PASSWORD) {
        $Registry.Password = $Env:SOGAR_REGISTRY_PASSWORD
    }

    if (![string]::IsNullOrEmpty($Url)) {
        $Registry.Url = $Url
    }

    if (![string]::IsNullOrEmpty($Username)) {
        $Registry.Username = $Username
    }

    if (![string]::IsNullOrEmpty($Password)) {
        $Registry.Password = $Password
    }

    $Registry
}

function Select-SogarRegistry
{
    [CmdletBinding()]
    param(
        [SogarRegistry] $Registry
    )

    $global:SOGAR_REGISTRY = $Registry
}

function Get-SogarRegistry
{
    [CmdletBinding()]
    param(
        [switch] $Current
    )

    $Registry = $global:SOGAR_REGISTRY

    if (-Not $Registry) {
        $Registry = New-SogarRegistry
        $global:SOGAR_REGISTRY = $Registry
    }

    $Registry
}

function Connect-SogarRegistry
{
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true,Position=0)]
        [string] $Url,
        [string] $Username,
        [string] $Password
    )

    if (![string]::IsNullOrEmpty($Url)) {
        $Env:SOGAR_REGISTRY_URL = $Url
    }

    if (![string]::IsNullOrEmpty($Username)) {
        $Env:SOGAR_REGISTRY_USERNAME = $Username
    }

    if (![string]::IsNullOrEmpty($Password)) {
        $Env:SOGAR_REGISTRY_PASSWORD = $Password
    }

    $Registry = New-SogarRegistry -Url:$Url -Username:$Username -Password:$Password

    Select-SogarRegistry $Registry
}

function Disconnect-SogarRegistry
{
    [CmdletBinding()]
    param(

    )

    if (![string]::IsNullOrEmpty($Url)) {
        Remove-Item Env:SOGAR_REGISTRY_URL
    }

    if (![string]::IsNullOrEmpty($Username)) {
        Remove-Item Env:SOGAR_REGISTRY_USERNAME
    }

    if (![string]::IsNullOrEmpty($Password)) {
        Remove-Item Env:SOGAR_REGISTRY_PASSWORD
    }

    Select-SogarRegistry $null
}

function Get-SogarAccessToken
{
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true,Position=0)]
        [string] $Reference,
        [string] $RegistryUrl,
        [string] $Username,
        [string] $Password,
        [string] $ServiceName,
        [SogarRegistry] $Registry
    )

    $RefParts = Split-SogarReference $Reference -NoTag
    $Repository = $RefParts.Repository
    $ImageName = $RefParts.Name

    if ($Registry) {
        if ([string]::IsNullOrEmpty($RegistryUrl)) {
            $RegistryUrl = $Registry.Url
        }
        if ([string]::IsNullOrEmpty($Username)) {
            $Username = $Registry.Username
        }
        if ([string]::IsNullOrEmpty($Password)) {
            $Password = $Registry.Password
        }
    }

    if ([string]::IsNullOrEmpty($ServiceName)) {
        $ServiceName = [System.Uri]::new($RegistryUrl).Host
    }

    $Scopes = @("repository:$Repository/$ImageName`:pull",
        "repository:$Repository/$ImageName`:pull,push")

    $PostParams = @{
        client_id = 'sogar';
        grant_type = 'password';
        username = $Username;
        password = $Password;
        scope = $($Scopes -Join ' ');
        service = $ServiceName;
    }

    $RequestParams = @{
        Method = 'POST';
        UseBasicParsing = $true;
        Uri = "$RegistryUrl/oauth2/token";
    }

    $Response = Invoke-WebRequest @RequestParams -Body $PostParams

    $ResponseContent = $Response.Content | ConvertFrom-Json

    $AccessToken = $ResponseContent.access_token

    $AccessToken
}

function Split-SogarReference
{
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true,Position=0)]
        [string] $Reference,
        [switch] $NoTag
    )

    $Match = $Reference | Select-String "(.*)/(.*):(.*)"

    if ($Match) {
        $MatchGroups = $Match.Matches.Groups
        [PSCustomObject]@{
            Repository = $MatchGroups[1].Value;
            Name = $MatchGroups[2].Value;
            Tag = $MatchGroups[3].Value;
        }
    } elseif ($NoTag) {
        $Match = $Reference | Select-String "(.*)/(.*)"

        if ($Match) {
            $MatchGroups = $Match.Matches.Groups
            [PSCustomObject]@{
                Repository = $MatchGroups[1].Value;
                Name = $MatchGroups[2].Value;
            }
        } else {
            $null
        }
    } else {
        $null
    }
}

function Split-SogarDigest
{
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true,Position=0)]
        [string] $Digest
    )

    $Parts = $($Digest -Split ':')
    $DigestType = $Parts[0]
    $DigestValue = $Parts[1]

    [PSCustomObject]@{
        Type = $DigestType;
        Value = $DigestValue;
    }
}

function Get-SogarMimeType
{
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true,Position=0)]
        [string] $FileName
    )

    $Extension = [IO.Path]::GetExtension($FileName)

    # https://developer.mozilla.org/en-US/docs/Web/HTTP/Basics_of_HTTP/MIME_types/Common_types

    $MimeMapping = @{
        ".zip" = "application/zip"
        ".bz" = "application/x-bzip"
        ".bz2" = "application/x-bzip2"
        ".tar" = "application/x-tar"
        ".7z" = "application/x-7z-compressed"
        ".pdf" = "application/pdf"

        ".json" = "application/json"
        ".js" = "text/javascript"
        ".htm" = "text/html"
        ".html" = "text/html"
        ".rtf" = "application/rtf"
        ".txt" = "text/plain"

        ".bmp" = "image/bmp"
        ".gif" = "image/gif"
        ".ico" = "image/x-icon"
        ".jpeg" = "image/jpeg"
        ".jpg" = "image/jpeg"
        ".png" = "image/png"
        ".svg" = "image/svg+xml"
        ".tif" = "image/tiff"
        ".tiff" = "image/tiff"
        ".webp" = "image/webp"

        ".mp4" = "video/mp4"
        ".mkv" = "video/x-matroska"
        ".mov" = "video/quicktime"
        ".avi" = "video/x-msvideo"
        ".wmv" = "video/x-ms-wmv"
        ".3gp" = "video/3gpp"
        ".flv" = "video/x-flv"
        ".webm" = "video/webm"

        ".mp3" = "audio/mpeg"
        ".wav" = "audio/wav"
        ".weba" = "audio/webm"
    }

    $MimeType = "application/octet-stream"

    if ($MimeMapping.Contains($Extension)) {
        $MimeType = $MimeMapping[$Extension]
    }

    $MimeType
}

function Invoke-SogarWebRequest
{
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true,Position=0)]
        [Hashtable] $RequestParams
    )

    if ($RequestParams['Method'] -eq 'HEAD') {
        if ($PSEdition -eq 'Core') {
            $RequestParams['SkipHttpErrorCheck'] = $true
        }
    }

    $OldProgressReference = $ProgressPreference
    $ProgressPreference = 'SilentlyContinue'

    $Response = try {
        Invoke-WebRequest @RequestParams -ErrorAction Stop
    } catch [System.Net.WebException] { 
        Write-Verbose "An exception was caught: $($_.Exception.Message)"
        $_.Exception.Response
    }

    $ProgressReference = $OldProgressPreference

    $Response
}

function Get-SogarManifest
{
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true,Position=0)]
        [string] $Reference,
        [string] $RegistryUrl,
        [string] $AccessToken,
        [SogarRegistry] $Registry,
        [SogarCache] $Cache
    )

    $RefParts = Split-SogarReference $Reference
    $Repository = $RefParts.Repository
    $ImageName = $RefParts.Name
    $ImageTag = $RefParts.Tag

    if ($Registry) {
        if ([string]::IsNullOrEmpty($RegistryUrl)) {
            $RegistryUrl = $Registry.Url
        }

        if ([string]::IsNullOrEmpty($AccessToken)) {
            $AccessToken = Get-SogarAccessToken $Reference -Registry $Registry
        }
    }

    $AcceptList = @(
        "application/vnd.docker.distribution.manifest.v2+json",
        "application/vnd.docker.distribution.manifest.list.v2+json",
        "application/vnd.oci.image.manifest.v1+json",
        "application/vnd.oci.image.index.v1+json",
        "*/*")
    
    $Headers = @{
        Accept = $($AcceptList -Join ",");
        Authorization = "Bearer $AccessToken";
    }
    
    $RequestParams = @{
        Method = 'GET';
        Headers = $Headers;
        UseBasicParsing = $true;
        Uri = "$RegistryUrl/v2/$Repository/$ImageName/manifests/$ImageTag";
    }
    
    $Response = Invoke-WebRequest @RequestParams

    $Cache = $Registry.Cache

    if ($Cache) {
        $ManifestFile = Join-Path $Cache.ManifestPath "$Repository/$ImageName/$ImageTag"
        New-Item -Path $(Split-Path $ManifestFile -Parent) -ItemType Directory -ErrorAction SilentlyContinue | Out-Null
        $AsByteStream = if ($PSEdition -eq 'Core') { @{AsByteStream = $true} } else { @{'Encoding' = 'Byte'} }
        Set-Content -Path $ManifestFile -Value $Response.Content @AsByteStream
    }
    
    $Manifest = [System.Text.Encoding]::UTF8.GetString($Response.Content) | ConvertFrom-Json

    $Manifest
}

function Save-SogarBlob
{
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true,Position=0)]
        [string] $Reference,
        [string] $RegistryUrl,
        [Parameter(Mandatory=$true)]
        [string] $MediaType,
        [Parameter(Mandatory=$true)]
        [string] $Digest,
        [Parameter(Mandatory=$true)]
        [string] $BlobPath,
        [string] $AccessToken,
        [SogarRegistry] $Registry,
        [SogarCache] $Cache
    )

    $RefParts = Split-SogarReference $Reference -NoTag
    $Repository = $RefParts.Repository
    $ImageName = $RefParts.Name

    if ($Registry) {
        if ([string]::IsNullOrEmpty($RegistryUrl)) {
            $RegistryUrl = $Registry.Url
        }

        if ([string]::IsNullOrEmpty($AccessToken)) {
            $AccessToken = Get-SogarAccessToken $Reference -Registry $Registry
        }
    }

    $DigestParts = Split-SogarDigest $Digest
    $DigestType = $DigestParts.Type
    $DigestValue = $DigestParts.Value

    $AcceptList = @($MediaType, "*/*")
    
    $Headers = @{
        Accept = $($AcceptList -Join ",");
        Authorization = "Bearer $AccessToken";
    }

    $DigestBlobPath = Join-Path $BlobPath $DigestType
    New-Item -Path $DigestBlobPath -ItemType Directory -ErrorAction SilentlyContinue | Out-Null

    $OutputBlobFile = Join-Path $DigestBlobPath $DigestValue

    if (Test-Path $OutputBlobFile -Type 'Leaf') {
        Write-Verbose "blob $DigestValue already found in local cache, skipping pull"
    } else {
        $RequestParams = @{
            Method = 'GET';
            Headers = $Headers;
            UseBasicParsing = $true;
            Uri = "$RegistryUrl/v2/$Repository/$ImageName/blobs/$Digest";
            OutFile = $OutputBlobFile
            Passthru = $true;
        }
    
        $Response = Invoke-SogarWebRequest $RequestParams
    }

    $OutputBlobFile
}

function Import-SogarArtifact
{
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true,Position=0)]
        [string] $Reference,
        [string] $AccessToken,
        [SogarRegistry] $Registry
    )

    $RefParts = Split-SogarReference $Reference
    $Repository = $RefParts.Repository
    $ImageName = $RefParts.Name

    if (-Not $Registry) {
        $Registry = Get-SogarRegistry -Current
    }

    if ([string]::IsNullOrEmpty($AccessToken)) {
        $AccessToken = Get-SogarAccessToken $Reference -Registry $Registry
    }

    $Cache = $Registry.Cache

    $Manifest = Get-SogarManifest -Registry $Registry -Reference $Reference `
        -Cache $Cache -AccessToken $AccessToken

    $ManifestConfig = $Manifest.Config
    $BlobFilePath = Save-SogarBlob -Reference $Reference -Registry $Registry -MediaType $ManifestConfig.MediaType `
        -Digest $ManifestConfig.Digest -BlobPath $Cache.BlobPath -Cache $Cache -AccessToken $AccessToken

    $Config = Get-Content -Path $BlobFilePath -Encoding UTF8 -ErrorAction Stop | ConvertFrom-Json

    foreach ($Layer in $Manifest.Layers) {
        $BlobFilePath = Save-SogarBlob -Reference $Reference -Registry $Registry -MediaType $Layer.MediaType `
            -Digest $Layer.Digest -BlobPath $Cache.BlobPath -Cache $Cache -AccessToken $AccessToken
    }
}

function Export-SogarBlob
{
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true,Position=0)]
        [string] $Reference,
        [Parameter(Mandatory=$true)]
        [string] $InputFile,
        [string] $MediaType,
        [string] $AccessToken,
        [SogarRegistry] $Registry
    )

    $RefParts = Split-SogarReference $Reference -NoTag
    $Repository = $RefParts.Repository
    $ImageName = $RefParts.Name

    if (-Not $Registry) {
        $Registry = Get-SogarRegistry -Current
    }

    $RegistryUrl = $Registry.Url

    if ([string]::IsNullOrEmpty($AccessToken)) {
        $AccessToken = Get-SogarAccessToken $Reference -Registry $Registry
    }

    $FileHash = Get-FileHash $InputFile -Algorithm 'SHA256'
    $DigestType = $FileHash.Algorithm.ToLower()
    $DigestValue = $FileHash.Hash.ToLower()
    $Digest = "$DigestType`:$DigestValue"

    $AcceptTypes = @("*/*")

    if ($MediaType) {
        $AcceptTypes = @($MediaType) + $AcceptTypes
    }

    # HEAD request

    $Headers = @{
        Authorization = "Bearer $AccessToken";
        Accept = $($AcceptTypes -Join ",");
    }

    $RequestParams = @{
        Method = 'HEAD';
        Headers = $Headers;
        UseBasicParsing = $true;
        Uri = "$RegistryUrl/v2/$Repository/$ImageName/blobs/$Digest";
    }

    $Response = Invoke-SogarWebRequest $RequestParams

    if ($Response.StatusCode -eq 200) {
        Write-Verbose "blob $DigestValue already found in registry, skipping push"
        return;
    }

    # POST request

    $Headers = @{
        "Authorization" = "Bearer $AccessToken";
        "Content-Length" = "0";
    }

    $RequestParams = @{
        Method = 'POST';
        Headers = $Headers;
        UseBasicParsing = $true;
        Uri = "$RegistryUrl/v2/$Repository/$ImageName/blobs/uploads/";
        ContentType = "application/octet-stream"
    }

    $Response = Invoke-WebRequest @RequestParams
    
    $PushLocation = $Response.Headers['Location']

    # PUT request

    $Headers = @{
        Authorization = "Bearer $AccessToken";
    }

    $RequestParams = @{
        Method = 'PUT';
        Headers = $Headers;
        UseBasicParsing = $true;
        Uri = "$RegistryUrl$PushLocation&digest=$Digest";
        ContentType = "application/octet-stream"
        InFile = $InputFile
        TimeoutSec = "36000"
    }

    $Response = Invoke-WebRequest @RequestParams
}

function Export-SogarManifest
{
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true,Position=0)]
        [string] $Reference,
        [Parameter(Mandatory=$true)]
        [string] $InputFile,
        [string] $MediaType,
        [string] $AccessToken,
        [SogarRegistry] $Registry
    )

    $RefParts = Split-SogarReference $Reference
    $Repository = $RefParts.Repository
    $ImageName = $RefParts.Name
    $ImageTag = $RefParts.Tag

    if (-Not $Registry) {
        $Registry = Get-SogarRegistry -Current
    }

    $RegistryUrl = $Registry.Url

    if ([string]::IsNullOrEmpty($AccessToken)) {
        $AccessToken = Get-SogarAccessToken $Reference -Registry $Registry
    }

    # https://github.com/opencontainers/image-spec/blob/master/manifest.md

    if (-Not $MediaType) {
        $MediaType = "application/vnd.oci.image.manifest.v1+json"
    }

    $FileHash = Get-FileHash $InputFile -Algorithm 'SHA256'
    $DigestType = $FileHash.Algorithm.ToLower()
    $DigestValue = $FileHash.Hash.ToLower()
    $Digest = "$DigestType`:$DigestValue"

    $AcceptTypes = @("*/*")

    if ($MediaType) {
        $AcceptTypes = @($MediaType) + $AcceptTypes
    }

    # HEAD request

    $Headers = @{
        Authorization = "Bearer $AccessToken";
        Accept = $($AcceptTypes -Join ",");
    }

    $RequestParams = @{
        Method = 'HEAD';
        Headers = $Headers;
        UseBasicParsing = $true;
        Uri = "$RegistryUrl/v2/$Repository/$ImageName/manifests/$ImageTag";
        SkipHttpErrorCheck = $true;
    }

    $Response = Invoke-SogarWebRequest $RequestParams

    # PUT request

    $Headers = @{
        Authorization = "Bearer $AccessToken";
    }

    $RequestParams = @{
        Method = 'PUT';
        Headers = $Headers;
        UseBasicParsing = $true;
        Uri = "$RegistryUrl/v2/$Repository/$ImageName/manifests/$ImageTag";
        ContentType = $MediaType;
        InFile = $InputFile
    }

    $Response = Invoke-WebRequest @RequestParams
}

function Export-SogarFileArtifact
{
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true,Position=0)]
        [string] $Reference,
        [Parameter(Mandatory=$true,Position=1)]
        [string] $InputFile,
        [string] $MediaType,
        [string] $MediaFileName,
        [string] $AccessToken,
        [SogarRegistry] $Registry
    )

    if (-Not $Registry) {
        $Registry = Get-SogarRegistry -Current
    }

    if (-Not $MediaType) {
        $MediaType = Get-SogarMimeType $InputFile
    }

    if (-Not (Test-Path -Path $InputFile -PathType 'Leaf')) {
        throw "`"$InputFile`" is not a directory"
    }

    if (-Not $MediaFileName) {
        $MediaFileName = $(Get-Item $InputFile).Name
    }

    $ArtifactFileSize = $(Get-Item $InputFile).Length

    $ArtifactFileHash = Get-FileHash $InputFile -Algorithm 'SHA256'
    $ArtifactDigestType = $ArtifactFileHash.Algorithm.ToLower()
    $ArtifactDigestValue = $ArtifactFileHash.Hash.ToLower()
    $ArtifactDigest = "$ArtifactDigestType`:$ArtifactDigestValue"

    $Annotations = [PSCustomObject]@{
        "org.opencontainers.image.title" = $MediaFileName
    }

    $Layer = [PSCustomObject]@{
        mediaType = $MediaType
        digest = $ArtifactDigest
        size = $ArtifactFileSize
        annotations = $Annotations
    }

    $Layers = @($Layer)

    # config manifest

    $TempConfig = [IO.Path]::ChangeExtension($(New-TemporaryFile), '.json')
    New-Item -Path $TempConfig -ItemType 'File' | Out-Null

    $ConfigFileHash = Get-FileHash $TempConfig -Algorithm 'SHA256'
    $ConfigFileSize = $(Get-Item $TempConfig).Length
    $ConfigDigestType = $ConfigFileHash.Algorithm.ToLower()
    $ConfigDigestValue = $ConfigFileHash.Hash.ToLower()
    $ConfigDigest = "$ConfigDigestType`:$ConfigDigestValue"

    # https://github.com/opencontainers/image-spec/blob/master/config.md

    $Config = [PSCustomObject]@{
        mediaType = "application/vnd.oci.image.config.v1+json"
        digest = $ConfigDigest
        size = $ConfigFileSize
    }

    # main manifest

    $Manifest = [PSCustomObject]@{
        schemaVersion = 2
        config = $Config
        layers = $Layers
    }

    $ManifestData = $Manifest | ConvertTo-Json -Depth 6 -Compress
    $ManifestBytes = $([System.Text.Encoding]::UTF8).GetBytes($ManifestData)
    $TempManifest = [IO.Path]::ChangeExtension($(New-TemporaryFile), '.json')

    $AsByteStream = if ($PSEdition -eq 'Core') { @{AsByteStream = $true} } else { @{'Encoding' = 'Byte'} }
    Set-Content -Path $TempManifest -Value $ManifestBytes @AsByteStream

    if ([string]::IsNullOrEmpty($AccessToken)) {
        $AccessToken = Get-SogarAccessToken $Reference -Registry $Registry
    }

    Export-SogarBlob $Reference -Registry $Registry -InputFile $InputFile -AccessToken $AccessToken
    Export-SogarBlob $Reference -Registry $Registry -InputFile $TempConfig -AccessToken $AccessToken

    Export-SogarManifest $Reference -Registry $Registry -InputFile $TempManifest -AccessToken $AccessToken
}

function Import-SogarFileArtifact
{
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true,Position=0)]
        [string] $Reference,
        [Parameter(Mandatory=$true,Position=1)]
        [string] $DestinationPath
    )

    $Registry = Get-SogarRegistry -Current

    $Cache = $Registry.Cache

    if ([string]::IsNullOrEmpty($AccessToken)) {
        $AccessToken = Get-SogarAccessToken $Reference -Registry $Registry
    }

    $Manifest = Get-SogarManifest -Registry $Registry -Reference $Reference `
        -Cache $Cache -AccessToken $AccessToken

    $ManifestConfig = $Manifest.Config
    $BlobFilePath = Save-SogarBlob -Reference $Reference -Registry $Registry -MediaType $ManifestConfig.MediaType `
        -Digest $ManifestConfig.Digest -BlobPath $Cache.BlobPath -Cache $Cache -AccessToken $AccessToken

    $Config = Get-Content -Path $BlobFilePath -Encoding UTF8 -ErrorAction Stop | ConvertFrom-Json

    foreach ($Layer in $Manifest.Layers) {
        $BlobFilePath = Save-SogarBlob -Reference $Reference -Registry $Registry -MediaType $Layer.MediaType `
            -Digest $Layer.Digest -BlobPath $Cache.BlobPath -Cache $Cache -AccessToken $AccessToken

        Copy-Item -Path $BlobFilePath -Destination $DestinationPath -Force
    }
}

function Export-SogarArchiveArtifact
{
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true,Position=0)]
        [string] $Reference,
        [Parameter(Mandatory=$true,Position=1)]
        [string] $Path,
        [string] $MediaType,
        [string] $MediaFileName,
        [string] $AccessToken,
        [SogarRegistry] $Registry
    )

    if (-Not $Registry) {
        $Registry = Get-SogarRegistry -Current
    }

    if (-Not $MediaType) {
        $MediaType = "application/zip"
    }

    $Path = Resolve-Path $Path

    if (-Not (Test-Path -Path $Path -PathType 'Container')) {
        throw "`"$Path`" is not a directory"
    }

    if (-Not $MediaFileName) {
        $MediaFileName = $(Get-Item $Path).Name
    }

    # compress layers

    $TempArchive = [IO.Path]::ChangeExtension($(New-TemporaryFile), '.zip')
    Compress-Archive -Path "$Path\*" -Destination $TempArchive

    $ArchiveFileHash = Get-FileHash $TempArchive -Algorithm 'SHA256'
    $ArchiveFileSize = $(Get-Item $TempArchive).Length
    $ArchiveDigestType = $ArchiveFileHash.Algorithm.ToLower()
    $ArchiveDigestValue = $ArchiveFileHash.Hash.ToLower()
    $ArchiveDigest = "$ArchiveDigestType`:$ArchiveDigestValue"

    $Annotations = [PSCustomObject]@{
        "org.opencontainers.image.title" = $MediaFileName
    }

    $Layer = [PSCustomObject]@{
        mediaType = $MediaType
        digest = $ArchiveDigest
        size = $ArchiveFileSize
        annotations = $Annotations
    }

    $Layers = @($Layer)

    # config manifest

    $TempConfig = [IO.Path]::ChangeExtension($(New-TemporaryFile), '.json')
    New-Item -Path $TempConfig -ItemType 'File' | Out-Null

    $ConfigFileHash = Get-FileHash $TempConfig -Algorithm 'SHA256'
    $ConfigFileSize = $(Get-Item $TempConfig).Length
    $ConfigDigestType = $ConfigFileHash.Algorithm.ToLower()
    $ConfigDigestValue = $ConfigFileHash.Hash.ToLower()
    $ConfigDigest = "$ConfigDigestType`:$ConfigDigestValue"

    $Config = [PSCustomObject]@{
        mediaType = "application/vnd.oci.image.config.v1+json"
        digest = $ConfigDigest
        size = $ConfigFileSize
    }

    # main manifest

    $Manifest = [PSCustomObject]@{
        schemaVersion = 2
        config = $Config
        layers = $Layers
    }

    $ManifestData = $Manifest | ConvertTo-Json -Depth 6 -Compress
    $ManifestBytes = $([System.Text.Encoding]::UTF8).GetBytes($ManifestData)
    $TempManifest = [IO.Path]::ChangeExtension($(New-TemporaryFile), '.json')

    $AsByteStream = if ($PSEdition -eq 'Core') { @{AsByteStream = $true} } else { @{'Encoding' = 'Byte'} }
    Set-Content -Path $TempManifest -Value $ManifestBytes @AsByteStream

    if ([string]::IsNullOrEmpty($AccessToken)) {
        $AccessToken = Get-SogarAccessToken $Reference -Registry $Registry
    }

    Export-SogarBlob $Reference -Registry $Registry -InputFile $TempArchive -AccessToken $AccessToken
    Export-SogarBlob $Reference -Registry $Registry -InputFile $TempConfig -AccessToken $AccessToken

    Export-SogarManifest $Reference -Registry $Registry -InputFile $TempManifest -AccessToken $AccessToken
}

function Import-SogarArchiveArtifact
{
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true,Position=0)]
        [string] $Reference,
        [Parameter(Mandatory=$true,Position=1)]
        [string] $DestinationPath
    )

    $Registry = Get-SogarRegistry -Current

    $Cache = $Registry.Cache

    if ([string]::IsNullOrEmpty($AccessToken)) {
        $AccessToken = Get-SogarAccessToken $Reference -Registry $Registry
    }

    $Manifest = Get-SogarManifest -Registry $Registry -Reference $Reference `
        -Cache $Cache -AccessToken $AccessToken

    $ManifestConfig = $Manifest.Config
    $BlobFilePath = Save-SogarBlob -Reference $Reference -Registry $Registry -MediaType $ManifestConfig.MediaType `
        -Digest $ManifestConfig.Digest -BlobPath $Cache.BlobPath -Cache $Cache -AccessToken $AccessToken

    $Config = Get-Content -Path $BlobFilePath -Encoding UTF8 -ErrorAction Stop | ConvertFrom-Json

    New-Item -Path $DestinationPath -ItemType 'Directory' -ErrorAction SilentlyContinue | Out-Null

    foreach ($Layer in $Manifest.Layers) {
        $BlobFilePath = Save-SogarBlob -Reference $Reference -Registry $Registry -MediaType $Layer.MediaType `
            -Digest $Layer.Digest -BlobPath $Cache.BlobPath -Cache $Cache -AccessToken $AccessToken

        Expand-Archive -Path $BlobFilePath -DestinationPath $DestinationPath -Force
    }
}
