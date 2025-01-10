sudo docker compose -f docker_compose.yml down
sudo docker image rm sztafeta:0.3-min
sudo docker compose -f docker_compose.yml up -d
sudo docker image ls
sudo docker compose -f docker_compose.yml logs