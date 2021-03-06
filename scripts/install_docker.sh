sudo apt-get -y update

sudo apt-get -y install apt-transport-https ca-certificates

sudo apt-key adv --keyserver hkp://p80.pool.sks-keyservers.net:80 --recv-keys 58118E89F3A912897C070ADBF76221572C52609D

echo "deb https://apt.dockerproject.org/repo ubuntu-trusty main" | sudo tee /etc/apt/sources.list.d/docker.list

sudo apt-get -y update

sudo apt-get -y install docker-engine

# Install recommended packages
#sudo apt-get install linux-image-extra-$(uname -r)

# Apparmor is required on Ubuntu 14.04
#sudo apt-get install apparmor
