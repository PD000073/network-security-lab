# Network Security Lab

A personal GitHub project focused on learning network security, CTF-style challenge solving, and offensive security fundamentals.

## Purpose

This repository contains small security exercises and challenge scripts exploring:

- networking basics
- service exploitation concepts
- packet analysis and protocol debugging
- CTF-style puzzle solving
- Python-based client/server experimentation

## Structure

- `exercises/pwn01_01/` – introductory challenge based on a simple authentication server
- `exercises/` – future labs and challenge files

## Current Exercise

### pwn01_01 – Intro challenge

This challenge simulates a basic authentication server and is a good first project for learning how to interact with vulnerable network services.

- `client.py` connects to the remote service and sends credentials
- `server.py` contains the challenge logic used by the service
- `task.md` explains the exercise context

## How to run

```bash
cd exercises/pwn01_01
python client.py
```

## Notes

This repository is intended for learning and practice. Use only on authorized systems and environments.
