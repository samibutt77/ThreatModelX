from models import User
import pyotp

mfa_secret = pyotp.random_base32()
User.create("admin", "AdminPassword123", "admin", mfa_secret)
print("Admin user created. MFA secret:", mfa_secret)
