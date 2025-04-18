# URL Detector

A web application that uses AI models to detect whether a URL is legitimate or malicious.

## Features

- User authentication (login, signup, profile management)
- Interactive chat interface for URL detection
- Dashboard with summary statistics and recent detections
- Two detection models:
  - Few-shot learning approach
  - Chain-of-thought reasoning approach
- Responsive design for desktop and mobile devices

## Tech Stack

- Backend: Python Flask
- Frontend: HTML, CSS, JavaScript
- AI Models: OpenAI, Google VertexAI, Deepseek, and other LLM providers
- Database: SQLite (local development)

## Setup and Installation

1. Clone the repository
2. Install dependencies:
   ```
   pip install -r requirements.txt
   ```
3. Create a `.env` file with your API keys:
   ```
   OPENAI_API_KEY=your_openai_api_key
   LANGCHAIN_API_KEY=your_langchain_api_key
   DEEPSEEK_API_KEY=your_deepseek_api_key
   GOOGLE_API_KEY=your_google_api_key
   HUGGINGFACE_API_KEY=your_huggingface_api_key
   GROQ_API_KEY=your_groq_api_key
   SECRET_KEY=your_secret_key_for_flask
   ```
4. Run the application:
   ```
   python app.py
   ```

## Deployment

This application is configured for deployment on Vercel:

1. Install Vercel CLI: `npm i -g vercel`
2. Run `vercel` from the project root
3. Follow the prompts to deploy

## License

MIT License 