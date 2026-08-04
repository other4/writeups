---
title: "Docker Compose Daily Workflow Cheat Sheet"
description: "A practical, zero-fluff reference guide for managing daily container lifecycles, debugging logs, and maintaining Docker environments efficiently."
author: [{"name": "Rajendra Pancholi", "email": "rpancholi522@gmail.com"}]
thumbnail: "/images/docker-daily.jpeg"
tags: [Docker, Docker-Compose, DevOps, Containerization, Backend]
keywords: ["Docker Compose cheat sheet", "Docker daily commands", "Docker compose logs", "How to rebuild docker container", "Docker system prune tutorial"]
---

# Docker Compose Daily Workflow Cheat Sheet

![Kubernetes Complete Tutorial](/images/docker-daily.jpeg)

## 1. Daily Workflow (Start & Watch)
- `docker compose up -d`: Starts everything in the background (detached mode).
- `docker compose logs -f`: Follows live logs for all services (e.g., viewing `morgan` or `testConnection`).
- `docker compose logs -f backend`: Focuses logs only on your Bun server. in this  `-f <service_name>`
- `docker compose ps`: Shows which containers are running and if any have "Exited" (crashed).
- `docker compose logs -f --tail 20 frontend` : See the last 20 lines and then follow

## 2. Stopping & Cleaning Up
- `CTRL + C`: Gracefully stops services if you are currently watching logs in the foreground.
- `docker compose stop`: The "Pause" button. Stops processes but keeps containers in memory for a fast `start`.
- `docker compose down`: The "Standard Cleanup." Stops and removes containers, freeing up RAM.
- `docker compose down -v`: The "Factory Reset." Stops containers and deletes your database data. Use this to re-run `init.sql`.

## 3. Handling Changes (Code & Packages)
- `docker compose up --build`: Use after `bun add <package>` or changing a Dockerfile to re-install dependencies.
- `docker compose restart <service>`: Reboots a specific part (e.g., `backend`) without touching the databases.
- `docker compose build --no-cache`: Use this if a build is failing or getting "stuck" on old data.
- `docker compose up -d --build --force-recreate frontent`

## 4. Interactive & Inside Commands
- `docker exec -it rktlrn-backend-1 sh`: Opens a terminal inside your running Bun container to check files.
- `docker exec -it rktlrn-mysql-1 mysql -u ruser -p`: Drops you into the MySQL shell inside the container.

## 5. System Maintenance & Troubleshooting
- `docker ps -a`: Lists all containers, including stopped or crashed ones, to debug boot failures.
- `docker stats`: Monitor real-time CPU and RAM usage for each container.
- `docker system prune`: Deletes all stopped containers and unused networks to save disk space.
- `docker images`: Lists all downloaded images and their sizes.

---
