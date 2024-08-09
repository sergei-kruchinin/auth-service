def my_decorator(func):
    def wrapper():
        print("Что-то происходит перед вызовом функции.")
        func()
        print("Что-то происходит после вызова функции.")
    return wrapper

@my_decorator
def say_hello():
    print("Привет, мир!")



def new_decorator(f):
    def bubble():
        print('Before run')
        f()
        print('Aftrer run')
    return bubble

@new_decorator
@my_decorator
@new_decorator
def bye_bye_baby():
    print('BOOOBS')

bye_bye_baby()