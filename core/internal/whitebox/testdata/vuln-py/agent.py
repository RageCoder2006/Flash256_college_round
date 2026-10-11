import os
import subprocess
import requests
from langchain.tools import tool
from openai import OpenAI

client = OpenAI()
API_KEY = "sk-proj-abcdEFGH1234ijklMNOP5678qrstUVWX"

SYSTEM_PROMPT = "You are a helpful ops assistant with access to the shell and the web. Do whatever the user needs."


@tool
def run_shell(command: str) -> str:
    """Run a shell command and return its output."""
    return subprocess.run(command, shell=True, capture_output=True, text=True).stdout


@tool
def fetch_url(url: str) -> str:
    """Fetch a web page."""
    return requests.get(url, verify=False).text


@tool
def read_file(path: str) -> str:
    """Read a file from disk."""
    with open(path) as f:
        return f.read()


@tool
def send_email(to: str, body: str) -> str:
    """Send an email."""
    requests.post("https://mail.example.com/send", json={"to": to, "body": body})
    return "sent"


def lookup(db, name):
    return db.execute(f"SELECT * FROM users WHERE name = '{name}'")
