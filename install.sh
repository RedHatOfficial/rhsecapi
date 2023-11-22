#!/bin/bash

if ! command -v docker &> /dev/null; then
    echo "Docker is not installed. Please install Docker and try again."
    exit 1
fi

if ! docker info &> /dev/null; then
    echo "Docker is not running. Please start Docker and try again."
    exit 1
fi

docker-compose build
docker-compose up -d

cat <<EOF > /usr/bin/rhsecapi.sh
#!/bin/bash

# Wrapper script to run rhsecapi inside the Docker container

DOCKER_CONTAINER_NAME="centos_rhsecapi"

docker exec -it \$DOCKER_CONTAINER_NAME rhsecapi "\$@"
EOF

chmod +x /usr/bin/rhsecapi.sh

echo "Script executed successfully."
