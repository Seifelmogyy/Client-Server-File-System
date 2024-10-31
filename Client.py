import requests
import json

BASE_URL = "https://localhost:8000"

def signup():
    """Handles user signup."""
    print("Create a new account:")
    username = input("Enter new username: ")
    password = input("Enter new password: ")

    response = requests.post(
        f"{BASE_URL}/signup",
        json={"username": username, "password": password},  
        verify='/Users/seifelmougy/Documents/GitHub/Client-Server-File-System/mykey.key',
        cert=('/Users/seifelmougy/Documents/GitHub/Client-Server-File-System/mykey.key','/Users/seifelmougy/Documents/GitHub/Client-Server-File-System/mycert.crt')
    )

    if response.status_code == 201:
        print("Account created successfully!")
    else:
        print("Failed to create an account.")
        print(f"Server response: {response.json()}")


def login(username, password):
    login_url = f"{BASE_URL}/login"
    credentials = {"username": username, "password": password}
    response = requests.post(login_url, json=credentials, verify="/Users/seifelmougy/Documents/GitHub/Client-Server-File-System/mykey.key")  # Disable SSL verification for testing

    if response.status_code == 200:
        data = response.json()
        if data["status"] == "success":
            print(f"Logged in successfully! User ID: {data['user_id']}")
            return data["user_id"]
        else:
            print("Login failed!")
    else:
        print("Error during login:", response.text)
    return None

def upload_file(user_id, file_path):
    upload_url = f"{BASE_URL}/upload"
    headers = {'User-ID': str(user_id)}
    with open(file_path, 'rb') as file:
        response = requests.post(upload_url, data=file, headers=headers, verify="/Users/seifelmougy/Documents/GitHub/Client-Server-File-System/mykey.key")

    if response.status_code == 200:
        print("File uploaded successfully!")
    else:
        print("File upload failed:", response.text)

def download_file(user_id, filename, save_path):
    download_url = f"{BASE_URL}/download"
    headers = {'User-ID': str(user_id), 'Filename': filename}
    response = requests.get(download_url, headers=headers, verify="/Users/seifelmougy/Documents/GitHub/Client-Server-File-System/mykey.key")

    if response.status_code == 200:
        with open(save_path, 'wb') as file:
            file.write(response.content)
        print("File downloaded successfully!")
    else:
        print("File download failed:", response.text)



def main():
    print("Welcome to the Client-Server File System")
    
    # Initial login/signup menu
    while True:
        print("1. Login")
        print("2. Sign up")
        choice = input("Choose an option (1 or 2): ")

        if choice == "1":
            user_id = login()
            if user_id:
                break
        elif choice == "2":
            signup()
        else:
            print("Invalid choice. Please enter 1 or 2.")

    # Main menu after successful login
    while True:
        print("\nMain Menu:")
        print("1. Upload file")
        print("2. Download file")
        print("3. Exit")
        
        option = input("Choose an option: ")

        if option == "1":
            upload_file(user_id)
        elif option == "2":
            download_file(user_id)
        elif option == "3":
            print("Goodbye!")
            break
        else:
            print("Invalid option. Please choose 1, 2, or 3.")

if __name__ == "__main__":
    main()
