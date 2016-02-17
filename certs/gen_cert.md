###Request the certificate
#####1. Run below command as administrator

lcscmd.exe /cert /action:request /sn:wildcard.cloudapp.net /exportable:true /ca:"pptestsubca.redmond.corp.microsoft.com\MS Passport Test Sub CA" /ou:azureoatuh /org:azureoatuh /country:US /state:WA /city:Redmond /friendlyName:wildcard.cloudapp.net /CaAccount:redmond\lsbvtta /CaPassword:***** /san:*.cloudapp.net,*.windows.net,*.windows-ppe.net,*.westus.cloudapp.azure.com /bitLength:2048

#####2. Export the certificate from certificate store with private key


#####3. Generate certs for Linux
a. Run openssl  pkcs12 -in ./AADOAuth.pfx -out AADOAuth.pem -nodes 

b. Copy -----BEGIN PRIVATE KEY----- to -----END PRIVATE KEY-----(includsive) and save it to AADOAuth.key

c. Copy the first -----BEGIN CERTIFICATE----- to -----END CERTIFICATE----- and save it to AADOAUth.crt

d. Copy the remaining and save it to AADOAUth.chain.pem

e. Generate public cert by running openssl x509 -inform PEM -in AADOAuth.crt > AADOAuth.pub
