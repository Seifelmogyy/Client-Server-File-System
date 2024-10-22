import requests
import json

BASE_URL = "https://localhost:8000"

def login(username, password):
    login_url = f"{BASE_URL}/login"
    credentials = {"username": username, "password": password}
    response = requests.post(login_url, json=credentials, verify=False)  # Disable SSL verification for testing

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
        response = requests.post(upload_url, data=file, headers=headers, verify=False)

    if response.status_code == 200:
        print("File uploaded successfully!")
    else:
        print("File upload failed:", response.text)

def download_file(user_id, filename, save_path):
    download_url = f"{BASE_URL}/download"
    headers = {'User-ID': str(user_id), 'Filename': filename}
    response = requests.get(download_url, headers=headers, verify=False)

    if response.status_code == 200:
        with open(save_path, 'wb') as file:
            file.write(response.content)
        print("File downloaded successfully!")
    else:
        print("File download failed:", response.text)

def show_menu():
    print("\nChoose an option:")
    print("1. Upload a file")
    print("2. Download a file")
    print("3. Exit")
    return input("Enter your choice: ")

def main():
    username = input("Enter your username: ")
    password = input("Enter your password: ")
    
    user_id = login(username, password)
    
    if user_id:
        while True:
            choice = show_menu()
            if choice == '1':
                file_path = input("Enter the path of the file to upload: ")
                upload_file(user_id, file_path)
            elif choice == '2':
                filename = input("Enter the name of the file to download: ")
                save_path = input("Enter the path to save the downloaded file: ")
                download_file(user_id, filename, save_path)
            elif choice == '3':
                print("Exiting the program.")
                break
            else:
                print("Invalid choice. Please try again.")

if __name__ == "__main__":
    main()
