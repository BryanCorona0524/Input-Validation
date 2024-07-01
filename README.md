Running the code:
-	Open Visual Studio.
-	Click on "File" in the top left corner and select "Open Folder".
-	Navigate to the folder where your Python code is located and select it.
-	Open the "Terminal" tab in Visual Studio by clicking on "View" and then "Terminal".
-	Install libraries by using command in terminal: pip install -r requirements.txt
-	In the terminal, navigate to the folder containing your Python code,
-	In our case keep the app.py tab open.
-	To run the app, type the command in terminal: uvicorn app:app --reload
-	Navigate to: http://127.0.0.1:8000/docs 
-	Logging in:
    I created some accounts ready to show the functionality of the application. Here are the two accounts you can use to authenticate with:
      1)	Username: johndoe with Password: 12345
      2)	Username: alice with Password: 56789  //this user will not be able to to do anything this they have the inactive variable set to true.
It is important to choose the “user” scope as it is a requirement for authentication, and you can choose between the “read” or both “read”/”write” scopes in order to test the roles requirements. The reason why I chose this method for authentication will be discussed later in this document.

Creating Docker Container:
-	Docker files are created and setup.
-	Build it using command: docker compose up --build
-	Navigate to: http://localhost:8000/docs/
-	Logging in:
I created some accounts ready to show the functionality of the application. Here are the two accounts you can use to authenticate with:
3)	Username: johndoe with Password: 12345
4)	Username: alice with Password: 56789 //this user will not be able to to do anything this they have the inactive variable set to true.
It is important to choose the “user” scope as it is a requirement for authentication, and you can choose between the “read” or both “read”/”write” scopes in order to test the roles requirements. The reason why I chose this method for authentication will be discussed later in this document.
