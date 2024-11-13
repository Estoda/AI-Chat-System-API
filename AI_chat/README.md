# AI Chat System API

## Installation Instructions

1. Clone the repository:
   ```bash
   git clone https://github.com/Estoda/AI-Chat-System-API.git
   cd AI_chat

2. Create a virtual environment:
   ```bash
   python -m venv myenv
   source myenv/bin/activate 

3. Install dependencies:
   ```bash
   pip install -r requirements.txt

4. Apply migrations:
   ```bash
   python3.11 manage.py migrate

5. Create a superuser (optional if you want to access Django admin):
   ```bash
   python3.11 manage.py createsuperuser

6. Run the development server:
   ```bash
   python3.11 manage.py runserver

7. API should now be accessible at http://127.0.0.1:8000/

## Endpoints

1. http://127.0.0.1:8000/register/ - Register a new user
2. http://127.0.0.1:8000/login/ - Log in and get an authentication token
3. http://127.0.0.1:8000/tokens/ - Get the user's remaining tokens
4. http://127.0.0.1:8000/chat/ - Send a message and get an AI-generated response

## Dependencies

1. Django==4.2.14
2. djangorestframework==3.15.2
3. djangorestframework-simplejwt==5.3.1
4. mysqlclient==2.2.4
5. virtualenv==20.26.3

## Example Input/Output:

* POST /register/:
   - Input:
      ```json
      {
         "username": "john_doe",
         "password": "password123"
      }

   - Output:
      ```json
      {
         "username": "john_doe"
      }

* POST /login/:
   - Input:
      ```json
      {
         "username": "john_doe",
         "password": "password123"
      }

   - Output:
      ```json
      {
         "user": "john_doe",
         "tokens": 4000,
         "token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpZCI6MiwiZXhwIjoxNzMxMzM1MjA2LCJpYXQiOjE3MzEzMzE2MDZ9.7jwy56sy2uB_kJRCjRmZAmalxtGYFTvFjuaDra-0S7E"
      }

* GET /tokens/:
   - Output:
      ```json
      {
         "username": "john_doe",
         "tokens": 4000
      }

* POST /chat/:
   - Input:
      ```json
      {
         "message": "Hi!"
      }

   - Output:
      ```json
      {
         "message": "Hi!",
         "response": "This is a dummy AI response.",
         "timestamp": "2024-11-11T13:29:59.216847Z",
         "remaining_tokens": 3900
      }



