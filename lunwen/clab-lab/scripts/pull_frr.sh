#!/bin/bash
docker pull frrouting/frr:latest 2>&1 | tail -3
docker images --format "{{.Repository}}:{{.Tag}} {{.Size}}"