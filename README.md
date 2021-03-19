# Simple OCI Generic Artifact Registry (SOGAR)

SOGAR is a generic implementation of [OCI Artifacts](https://github.com/opencontainers/artifacts) in PowerShell and other languages. I have only tested it against [Azure Container Registry](https://azure.microsoft.com/en-us/services/container-registry/). You can read more about how [ACR supports OCI Artifacts here](https://docs.microsoft.com/en-us/azure/container-registry/container-registry-oci-artifacts).

Open a new PowerShell terminal, and import the Sogar PowerShell module:

```powershell
Import-Module ".\powershell\Sogar\Sogar.psm1"
```

Start by defining environment variables to point to the your ACR URL, username and password.

```powershell
$Env:SOGAR_REGISTRY_URL="https://myrepo.azurecr.io"
$Env:SOGAR_REGISTRY_USERNAME="myadmin"
$Env:SOGAR_REGISTRY_PASSWORD="solarwinds123"
```

Push a video file as an OCI artifact:

```powershell
Export-SogarFileArtifact "videos/demo:latest" ".\VideoDemo1.mp4" -MediaType "video/mp4"
```

If you don't specify a media type for the file, a default one will be obtained from the file extension.

Pull the same video file again using a different file name:

```powershell
Import-SogarFileArtifact "videos/demo:latest" ".\VideoDemo2.mp4"
```

Compare the video files to confirm that they are the same:

```powershell
PS > Get-FileHash ".\VideoDemo*.mp4"

Algorithm       Hash                                                                   Path
---------       ----                                                                   ----
SHA256          71F263E6E77DF6B1AE79EED6FA0DAF20BDEC758550932EA6E7FE39F938F47CE2       VideoDemo1.mp4
SHA256          71F263E6E77DF6B1AE79EED6FA0DAF20BDEC758550932EA6E7FE39F938F47CE2       VideoDemo2.mp4
```

Congratulations, you have just pushed an artifact to an OCI registry with a name and tag, and then pulled the same artifact from the OCI registry again. You can repeat the process for any kind of file you like!
