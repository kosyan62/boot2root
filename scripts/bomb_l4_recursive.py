
def func4(num):

    if num < 2:
        var2 = 1

    else:
        var1 = func4(num - 1)
        var2 = func4(num - 2)
        var2 = var1 + var2
    return var2

if __name__ == "__main__":
    a = int(input())
    print(func4(a))
