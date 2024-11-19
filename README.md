# Client-Server-File-System

This project implements a client-server application that allows users to sign up, log in, upload files, list files, and download files. The server ensures that each user has access to only their own files, with a separate folder for each user.

## Features

- **User Authentication**: Users can sign up and log in securely.
- **File Management**: Users can upload, list, and download their files.
- **Personalized Folders**: Each user has their own folder, where they can only see and interact with their files.
- **Client-Server Architecture**: The application uses a client-server model to handle file operations.

## Installation

### Prerequisites

- Python 3.x
- SQLite (or your choice of database)

### Set Up

1. Clone this repository to your local machine:

   ```bash
   git clone https://github.com/yourusername/file-upload-client-server.git
   cd file-upload-client-server
