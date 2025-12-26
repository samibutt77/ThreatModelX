class UserModel:
    def save(self):
        pass

class UserService:
    def create_user(self):
        u = UserModel()
        u.save()

def main():
    service = UserService()
    service.create_user()
