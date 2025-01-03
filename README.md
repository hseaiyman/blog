# Tweaker Blog

A modern, minimalist blog platform built with Flask and styled with Tailwind CSS.

## Features

- User authentication with email registration
- Create and view blog posts
- Comment on posts
- Markdown support for post content
- Responsive design with animations
- Clean and modern UI with Tailwind CSS

## Setup

1. Create a virtual environment:
```bash
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
```

2. Install dependencies:
```bash
pip install -r requirements.txt
```

3. Set up environment variables:
   - Copy `.env.example` to `.env`
   - Update the values in `.env` with your configuration
   - Key variables to set:
     - SECRET_KEY: Your secure secret key
     - DATABASE_URL: Your database URL
     - FLASK_ENV: Set to 'production' for production environment

4. Initialize the database:
```bash
python init_db.py
```

5. Create an admin user:
```bash
python create_user.py
```

## Development

Run the development server:
```bash
python app.py
```

## Contributing

Pull requests are welcome. For major changes, please open an issue first to discuss what you would like to change.

## License

[MIT](https://choosealicense.com/licenses/mit/)
