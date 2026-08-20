#!/bin/bash
echo "=== container start time vs now ==="
date
docker inspect asc-asscor-host1 --format '{{.State.StartedAt}} {{.Created}}' 2>&1
echo "=== eth interfaces in host1 ==="
docker exec asc-asscor-host1 ls /sys/class/net/ 2>&1
echo "=== clab graph - all links ==="
clab inspect -t ~/clab/asscor/asscor.clab.yml 2>&1 | grep -cE 'asc-asscor'
echo "=== try clab deploy --reconfigure ==="
cd ~/clab/asscor
sudo clab deploy -t asscor.clab.yml --reconfigure 2>&1 | tail -8
echo DONE
