import turtle as t


with open('turtle', 'r') as fp:
    for n, line in enumerate(fp, 1):
        # Hadle one line
        arr = line.split(' ')
        if arr[0] == 'Avance':
            t.fd(int(arr[1]))
        elif arr[0] == 'Recule':
            t.bk(int(arr[1]))
            print('BACK')
        elif arr[0] == 'Tourne':
            deg = int(arr[3])
            if arr[1] == 'droite':
                t.right(deg)
            else:
                t.left(deg)
        else:
            input()
            t.clear()

