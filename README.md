# pegacorn-postgresql

This project creates a secure [Postgres](https://www.postgresql.org/) docker image configured for certificate authentication only for a single user called pegacorn (as defined in pg_hba.conf).
During the creation of the database the creation of a credential with a password is avoided so there is no potential to by-pass the certificate based authentication.
Encrypted connections are forced as there are only hostssl entries in pg_hba.conf (as per https://dba.stackexchange.com/questions/8580/force-postgresql-clients-to-use-ssl).

The following certificates need to be provided to the docker image via a host volume (defined in the hostPathCerts helm chart variable), so all possible nodes that can host this docker container must have these available:
1. $KUBERNETES_SERVICE_NAME.$MY_POD_NAMESPACE.key - private key for the server certificate
2. $KUBERNETES_SERVICE_NAME.$MY_POD_NAMESPACE.cer - server certificate
3. ca.cer - the Certificate Authority certificate chain to trust
The certificates can be created by following [How to create certificates](#how-to-create-certificates)

# Copy the host-files to the DockerDesktop VM
Following https://nickjanetakis.com/blog/docker-tip-70-gain-access-to-the-mobylinux-vm-on-windows-or-macos
```
docker container run --rm -it -v /:/host alpine
> chroot /host
> mkdir -p /kube-vols
> cp -r /host_mnt/c/host-files/* /kube-vols/
# NOTE: sometimes files are cached for some unknown reason, so copy to new file names in Windows, transfer to the DockerDesktop VM, delete the old file, then move the new file name to the desired file name
> exit
```

The pegacorn-postgres database can run in two modes:
1. The helm-data-can-be-lost helm chart: Postgres storage of a single instance behind a kubernetes service that is a "persisted cache" with no reliance on needing the data on restart.  The data is NOT replicated or stored on persistent storage, so if a node crashes, the data will be lost.  So applications using this need to be able to recreate the data e.g. keycloak authorisation, which is why the description "persisted cache" is used.
2. The helm-postgres helm chart: Postgres storage of one or more instances (one instance per Kubernetes node denoted by a Kubernetes node label e.g. fhirplace=Yes or hestia=Yes), with persistent storage attached to the node.  Logical replication is achieved by the calling java code (e.g. pegacorn-hapi-fhir-jpaserver) using pegacorn-petasos.  See Design/DESIGN-Highly-available-Postgres-in-a-site-using-petasos.txt for more detail.  

# To create the docker image
```
cd <To the directory where you have git cloned this project>
docker build --rm -t pegacorn/pegacorn-postgres:1.0.0-snapshot --file Dockerfile .
```

# To run on an existing Kubernetes cluster with helm
```
kubectl create namespace site-a
kubectl create namespace site-b
kubectl config set-context site-a --namespace=site-a --cluster=<Your cluster name e.g. docker-desktop> --user=[Your cluster user e.g. docker-desktop]
kubectl config set-context site-b --namespace=site-a --cluster=<Your cluster name e.g. docker-desktop> --user=[Your cluster user e.g. docker-desktop]

kubectl label nodes <Node name to run postgres on e.g. docker-desktop> fhirplace=Yes
kubectl label nodes <Node name to run postgres on e.g. docker-desktop> hestia=Yes

# If you are running a Highly Available Cluster of Kubernetes nodes, a Kubernetes secret to connect to your docker registry will need to be created
  kubectl create secret docker-registry acr-secret-site-a --namespace site-a --docker-server=https://<your docker registry>.azurecr.io --docker-username=<service-principal-username> --docker-password="<service-principal-password>"
  # and then on each of the helm commands the following values must be added to the comma delimited list of values:
  # ,acrSecretName=acr-secret-site-a,dockerRepo=<your docker registry>.azurecr.io/,imagePullPolicy=Always

cd <To the directory where you have git cloned this project>
helm upgrade pegacorn-fhirplace-site-a --install --namespace site-a --set serviceName=pegacorn-fhirplace,nodeAffinityLabel=fhirplace,hostPath=/kube-vols/fhirplace-site-a/data,hostPathCerts=/kube-vols/certificates,basePort=30000,imageTag=1.0.0-snapshot,dbUser=pegacorn,dbName=hapi,serviceType=NodePort helm-postgres

helm upgrade pegacorn-hestia-dam-site-a --install --namespace site-a --set serviceName=pegacorn-hestia-dam,nodeAffinityLabel=hestia,hostPath=/kube-vols/hestia-dam-site-a/data,hostPathCerts=/kube-vols/certificates,basePort=30010,imageTag=1.0.0-snapshot,dbUser=pegacorn,dbName=hapi,serviceType=NodePort helm-postgres

# NOTE: for the helm-data-can-be-lost chart, the nodeAffinityLabel is optional and only a preferredDuringSchedulingIgnoredDuringExecution, so the pods will 
# still be scheduled even if the nodeAffinityLabel is specified but there are no active nodes with that label
helm upgrade pegacorn-authorisation-storage-site-a --install --namespace site-a --set serviceName=pegacorn-authorisation-storage,nodeAffinityLabel=authorisation-storage,hostPath=/kube-vols/authorisation-storage-site-a/data,hostPathCerts=/kube-vols/certificates,basePort=30020,imageTag=1.0.0-snapshot,dbUser=pegacorn,dbName=keycloak helm-data-can-be-lost
```

# To test everything is working
* Download https://www.pgadmin.org/ for Windows - https://ftp.postgresql.org/pub/pgadmin/pgadmin4/v4.14/windows/pgadmin4-4.14-x86.exe and install
* Right click on "Servers" and select Create -> Server
* Set the name to be local
* On the Connection tab set
  * Hostname: localhost
  * Port: 30000
* Click on Save and confirm that the connection is NOT successful with error messages:
```
Unable to connect to server:
FATAL: pg_hba.conf rejects connection for host "<IP Address>", user "postgres", database "postgres", SSL on
FATAL: no pg_hba.conf entry for host "<IP Address>", user "postgres", database "postgres", SSL off
```
* Change the Username to pegacorn
* Click on Save and confirm that the connection is NOT successful with error messages:
```
Unable to connect to server:
FATAL: connection requires a valid client certificate
FATAL: no pg_hba.conf entry for host "<IP Address>", user "pegacorn", database "postgres", SSL off
```
* On the SSL tab set
  * SSL mode: Verify-Full
  * Client certificate: C:\host-files\certificates\pegacorn.cer
  * Client certificate key: C:\host-files\certificates\pegacorn.key
  * Root certificate: C:\host-files\certificates\ca.cer
* Click on Save and confirm that the connection is successful
From https://medium.com/@pavelevstigneev/postgresql-ssl-with-letsencrypt-b53051eacc22
* In pgAdmin select the Tools -> Query Tool menu option and run the following 2 sql statements:
```
SELECT * from pg_catalog.pg_stat_ssl
```
```
SELECT ssl.pid, usename, datname, ssl, client_addr, backend_type, wait_event
FROM pg_catalog.pg_stat_ssl ssl, pg_catalog.pg_stat_activity a
WHERE ssl.pid = a.pid
```

# How to create certificates
Following https://docs.microsoft.com/en-us/dotnet/framework/wcf/feature-details/how-to-create-temporary-certificates-for-use-during-development#installing-a-certificate-in-the-trusted-root-certification-authorities-store

* Open a new Windows PowerShell as as Administrator
```
C:
cd \host-files\certificates
# Root CA certificate: 
# NOTE: skip this step if an existing Root CA certificate already exists
# NOTE: other environments will not use self signed certificates but the general idea is the same.  
$rootcert = New-SelfSignedCertificate -CertStoreLocation Cert:\LocalMachine\My -DnsName "localhostRootCA" -TextExtension @("2.5.29.19={text}CA=true") -NotAfter (Get-Date).AddYears(10) -KeyUsage CertSign,CrlSign,DigitalSignature
[String]$rootCertPath = Join-Path -Path 'cert:\LocalMachine\My\' -ChildPath "$($rootcert.Thumbprint)"
Export-Certificate -Cert $rootCertPath -FilePath 'ca.crt'
certutil -encode ca.crt ca.cer
rm ca.crt
```

* Using Cortana search in Windows 10, type "certificate" until you see the "Manage **computer** certificates" option and open it
* In the left panel, navigate to Certificates - Local Computer → Trusted Root Certification Authorities → Certificates
* Right-click the Certificates folder and click All Tasks, then click Import.
* Follow the on-screen wizard instructions to import C:\host-files\certificates\ca.cer into the store.

From https://wiki.cac.washington.edu/display/infra/Extracting+Certificate+and+Private+Key+Files+from+a+.pfx+File
* Install https://slproweb.com/download/Win64OpenSSL-1_1_1d.exe
* Open a new Command Prompt opened as an administrator
```
setx /m PATH "%PATH%;C:\Program Files\OpenSSL-Win64\bin"
```

* Open a new Windows PowerShell as as Administrator
```
# NOTE: for the keystore the password must match the password of the imported key to avoid "java.security.UnrecoverableKeyException: Cannot recover key" Exceptions. 
# NOTE: Also tried changing the keypassword to match the keystorepass but then got "java.security.UnrecoverableKeyException: Password verification failed" exceptions
# NOTE: this function requires that C:\host-files\certificates\ca.cer be imported as a Trusted Root Certification Authority as detailed above.
# NOTE: the resulting .cer and .key files are in the PEM format
function Create-Cert-Set() {
    Param(
        [Parameter(Mandatory=$true)][String]$certSubject,
        [Parameter(Mandatory=$true)][String]$certPwd,
        [Parameter(Mandatory=$false)][bool]$createKeystore,
        [Parameter(Mandatory=$false)][String]$truststorePwd,
        [Parameter(Mandatory=$false)][bool]$createPk8WithNoPassPhraseForPostgresClientAuth
    )
    $rootcert = Get-ChildItem -Path cert:\LocalMachine\My | Where-Object {$_.Subject -eq "CN=localhostRootCA"}
    [System.Security.SecureString]$certPwdSecure = ConvertTo-SecureString -String $certPwd -Force -AsPlainText
    $cert = New-SelfSignedCertificate -CertStoreLocation Cert:\LocalMachine\My -DnsName $certSubject -KeyExportPolicy Exportable -KeyLength 2048 -KeyUsage DigitalSignature,KeyEncipherment -Signer $rootCert -NotAfter (Get-Date).AddYears(10)
    [String]$certPath = Join-Path -Path 'cert:\LocalMachine\My\' -ChildPath "$($cert.Thumbprint)"
    Export-PfxCertificate -Cert $certPath -FilePath ($certSubject + ".pfx") -Password $certPwdSecure
    Export-Certificate -Cert $certPath -FilePath ($certSubject + ".crt")
    certutil -encode ($certSubject + ".crt") ($certSubject + ".cer")
    rm ($certSubject + ".crt")
    openssl pkcs12 -in ($certSubject + ".pfx") -nocerts -out ($certSubject + ".pem") -nodes -passin ("pass:" + $certPwd)
    openssl rsa -in ($certSubject + ".pem") -out ($certSubject + ".key")
    if($createPk8WithNoPassPhraseForPostgresClientAuth) {
        openssl pkcs8 -topk8 -inform PEM -in ($certSubject + ".pem") -outform DER -out ($certSubject + ".pk8") -v1 PBE-MD5-DES -nocrypt
    }
    rm ($certSubject + ".pem")
    if($createKeystore) {
        keytool -import -keystore ($certSubject + ".jks") -file ca.cer -alias root -storepass $certPwd -noprompt
        openssl pkcs12 -export -in ($certSubject + ".cer") -inkey ($certSubject + ".key") -out ($certSubject + ".p12") -name $certSubject -CAfile ca.cer -caname root -chain -passout ("pass:" + $certPwd)
        keytool -importkeystore -deststorepass $certPwd -destkeypass $certPwd -destkeystore ($certSubject + ".jks") -srckeystore ($certSubject + ".p12") -srcstoretype PKCS12 -srcstorepass $certPwd -alias $certSubject
        rm ($certSubject + ".p12")
    }
    if(($truststorePwd -ne $null) -and ($truststorePwd -ne "")) {
        keytool -import -keystore ($certSubject + "-cert.jks") -file ca.cer -alias root -storepass $truststorePwd -noprompt
        keytool -import -keystore ($certSubject + "-cert.jks") -file ($certSubject + ".cer") -alias $certSubject -storepass $truststorePwd -noprompt
    }
}

C:

# Server certificate:
# NOTE: skip this step if the Server certificate with the subject name you require already exists
cd \host-files\certificates
Create-Cert-Set -certSubject "pegacorn-fhirplace.site-a" -certPwd "FhirPlaceSiteA123"

# Client certificate:
# NOTE: skip this step if the Client certificate with the subject name you require already exists
# NOTE: the pk8/pkcs8 file is created for client certificate authentication with Postgres. The -nocrypt option is used to avoid a passphrase being required.
# The file when deployed should have only owner read permissions.
# From https://jdbc.postgresql.org/documentation/head/connect.html
Create-Cert-Set -certSubject "pegacorn" -certPwd "Pegacorn123" -createPk8WithNoPassPhraseForPostgresClientAuth $True
```

