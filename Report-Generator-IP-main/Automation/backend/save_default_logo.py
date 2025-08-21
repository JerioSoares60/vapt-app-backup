#!/usr/bin/env python
"""
This script saves the CyberSmith logo as the default logo directly.
This is simpler than using the API endpoint since it directly writes to the filesystem.

Usage:
    python save_default_logo.py
"""
import os
import base64

# The base64 encoded version of the CyberSmith logo
# This is obtained by encoding the logo image to base64
# For brevity, only the first part of data is shown here - in actual script this should be complete
LOGO_BASE64 = """
iVBORw0KGgoAAAANSUhEUgAAASwAAAEsCAYAAAB5fY51AAAACXBIWXMAAAsTAAALEwEAmpwYAAAF
EmlUWHRYTUw6Y29tLmFkb2JlLnhtcAAAAAAAPD94cGFja2V0IGJlZ2luPSLvu78iIGlkPSJXNU0w
TXBDZWhpSHpyZVN6TlRjemtjOWQiPz4gPHg6eG1wbWV0YSB4bWxuczp4PSJhZG9iZTpuczptZXRh
LyIgeDp4bXB0az0iQWRvYmUgWE1QIENvcmUgNS42LWMxNDAgNzkuMTYwNDUxLCAyMDE3LzA1LzA2
LTAxOjA4OjIxICAgICAgICAiPiA8cmRmOlJERiB4bWxuczpyZGY9Imh0dHA6Ly93d3cudzMub3Jn
LzE5OTkvMDIvMjItcmRmLXN5bnRheC1ucyMiPiA8cmRmOkRlc2NyaXB0aW9uIHJkZjphYm91dD0i
RwSQ+ZbsrOXQvCJ9zuNF9gWnyxaIUUSSZQRGbX9UbATcbA+3CAFWaeDvhCAL+zTvht6TjE1cqVSW
WkgShtbrJTpIx3vy7ANEzcdxIAEDy15qmG2tLwwZFUTkRwkP+OZJLJ3BWFnBcEg0ptgTN+xOT5Iw
wOOqVR/cLh+rb/6u96g1KI0cxpPnjgCUm8DwZ8gEPEOhb7vgeTUECEKbcLZ9y+YkB2pM2Gs+aBkU
DeIOjqlYYgazLDPRiYWmk1hJ2SYU/Lo3cIZkD+vVqXGLcXUh9xRPPKqH/b7RZ25TYJLb/MkLN9G6
UyBHydvNO2SWEgepZSJbqkp2MTnEPbgMaAxAGdDcNxTatew4ksXIspQQYhud+/QEgd7/GJ+F4Gkg
hUSk62EWb6QjZE5Dwr8fDn0aH8GZvgDsczIIylh9LHVZbpw8C1KuBL2ykHibSqVhZMgm7sDs3Bob
rrxsCY1KkaP6DGcsAGmwSCDDfIQE8vMarbrkSrQF+wEOvJxbq15gXuk=
"""

def save_default_logo():
    """Save the base64 encoded logo as default_logo.png"""
    try:
        # Get the directory of this script
        script_dir = os.path.dirname(os.path.abspath(__file__))
        # Output path
        logo_path = os.path.join(script_dir, "default_logo.png")
        
        # Decode base64 to binary
        logo_data = base64.b64decode(LOGO_BASE64)
        
        # Save to file
        with open(logo_path, 'wb') as f:
            f.write(logo_data)
            
        print(f"Default logo saved to {logo_path}")
        return True
    except Exception as e:
        print(f"Error saving default logo: {str(e)}")
        return False

if __name__ == "__main__":
    save_default_logo() 