# Setting Up the Default Logo

The report generator allows users to add their company logo to the generated reports. If no logo is provided, a default logo will be shown.

## How to Set Up the Default Logo

### Method 1: Direct File Placement

1. Save the CyberSmith logo image as `default_logo.png` 
2. Place it in the `backend` directory alongside `main.py`

### Method 2: Using the Backend API

1. Start the FastAPI backend server:
   ```
   cd Automation2.0/backend
   uvicorn main:app --reload --port 8004
   ```

2. Use the `setup_default_logo.py` script to upload the logo:
   ```
   python setup_default_logo.py --logo path_to_logo_image.png
   ```

### Method 3: Using the save_default_logo.py Script

1. If you already have the CyberSmith logo image and the base64 data in `save_default_logo.py` is correct:
   ```
   cd Automation2.0/backend
   python save_default_logo.py
   ```

2. If you need to update the base64 data in `save_default_logo.py`, convert your image to base64:
   ```python
   import base64
   
   # Read the image
   with open('path_to_your_logo.png', 'rb') as img:
       img_data = img.read()
   
   # Convert to base64
   b64_str = base64.b64encode(img_data).decode('utf-8')
   print(b64_str)
   ```

3. Copy the base64 output and replace the `LOGO_BASE64` variable content in `save_default_logo.py`

## Logo Usage

- When a user uploads their own logo in the frontend, it will be used instead of the default logo
- The logo will be placed in the report where the template has the variable `{{company_logo}}`
- For optimal display, the logo should be:
  - PNG or JPG format
  - Aspect ratio close to 3:1 (width:height)  
  - Height of approximately 100-200 pixels 