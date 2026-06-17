import re
import base64
import requests

url = 'http://localhost:3001'
s = requests.Session()

# Register a regular user
resp = s.get(url + '/register')
print('register page', resp.status_code)
match = re.search(r'name="_csrf" value="([^"]+)"', resp.text)
print('csrf register', bool(match))
csrf = match.group(1) if match else ''
resp = s.post(url + '/register', data={
    'displayName': 'Test User',
    'email': 'testuser@example.com',
    'password': 'Test1234!@#$',
    '_csrf': csrf
}, allow_redirects=False)
print('register post', resp.status_code, resp.headers.get('location'))

# Fetch profile page after registration
resp = s.get(url + '/profile')
print('profile page', resp.status_code)
match = re.search(r'name="_csrf" value="([^"]+)"', resp.text)
print('csrf profile', bool(match))
csrf = match.group(1) if match else ''

# Save test image and upload
img_data = base64.b64decode('iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR4nGMAAQAABQABDQottAAAAABJRU5ErkJggg==')
with open('test.png', 'wb') as f:
    f.write(img_data)

with open('test.png', 'rb') as img:
    resp = s.post(url + '/profile/upload-picture', files={
        'profilePicture': ('test.png', img, 'image/png')
    }, data={'_csrf': csrf}, allow_redirects=False)

print('upload status', resp.status_code)
print('location', resp.headers.get('location'))
print(resp.text[:400])
