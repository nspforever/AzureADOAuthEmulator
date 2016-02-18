#sudo docker pull nspforever/azure-ad-oauth2-emulator
sudo docker run -d \
-p 4443:4443 \
-p 8080:8080 \
--restart=always \
-e PRIVATE_KEY_PATH=/AzureADOAuthEmulator/certs/AADOAuth.key \
-e PUBLIC_CERT_PATH=/AzureADOAuthEmulator/certs/AADOAuth.pub \
nspforever/azure-ad-oauth2-emulator