import string
def phase_5(string):
    var1 = len(string)
    if var1 != 6:
        print("Failure length")
        return
    var1 = 0
    const_arr = "isrveawhobpnutfg\xb0\x01"
    arr = []
    while (var1 < 6):
        arr.append(const_arr[ord(string[var1]) & 0xf])
        print(f"{'giants'[var1]} =? {const_arr[ord(string[var1]) & 0xf]}; ind = {ord(string[var1]) & 0xf}")
        var1 += 1
    if arr != list("giants"):
        print(str(arr), "giants") 
        print("Filure")
    else:
        print("You're good")

def print_indexes():
    abc = string.ascii_lowercase
    for letter in abc:
        ind = ord(letter) & 0xf
        print(f"{letter} = {ind}")

if __name__ == "__main__":
    inp = input()
    print_indexes()
    phase_5(inp)
