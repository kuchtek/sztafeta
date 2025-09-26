sudo docker compose -f docker_compose.yml down
sudo docker rmi $(sudo docker images | grep 'sztafeta')
sudo docker compose -f docker_compose.yml up -d
sudo docker image ls
sudo docker compose -f docker_compose.yml logs