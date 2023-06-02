import hashlib
import random
from sympy import isprime

class NybergRueppel:
    # Алгоритм Ніберга-Рюппеля

    def mod_inv(self, a, m):
        """
        Обернене число за модулем.
        :param a: Число, для якого шукаємо обернене за модулем.
        :param m: Модуль.
        :return: Обернене число за модулем.
        """
        if a < 0:
            a = m + (a % m)
        _, x, _ = self.gcd(a, m)
        return x % m

    def generate_prime(self, bit_length):
        """
        Генерує випадкове просте число заданої довжини в бітах.
        :param bit_length: Довжина в бітах.
        :return: Випадкове просте число.
        """
        while True:
            p = random.getrandbits(bit_length)
            if isprime(p):
                return p

    def gcd(self, a, b):
        """
        Знаходить найбільший спільний дільник двох чисел.
        :param a: Перше число.
        :param b: Друге число.
        :return: Найбільший спільний дільник та числа x, y для рівняння ax + by = gcd(a, b).
        """
        if a == 0:
            return b, 0, 1
        gcd, x1, y1 = self.gcd(b % a, a)
        x = y1 - (b // a) * x1
        y = x1
        return gcd, x, y

    def sign(self, message, private_key):
        """
        Підписує повідомлення за приватним ключем.
        :param message: Повідомлення, яке підписується.
        :param private_key: Приватний ключ.
        :return: Підпис повідомлення.
        """
        p, q, g, y, x = private_key
        h = int(hashlib.sha256(message.encode()).hexdigest(), 16)
        k = random.randint(2, q - 1)
        r = pow(g, k, p) % q
        s = (self.mod_inv(k, q) * (h + x * r)) % q
        return (r, s)

    def check(self, message, signature, public_key):
        """
        Перевіряє підписане повідомлення за публічним ключем.
        :param message: Повідомлення, яке перевіряється.
        :param signature: Підпис повідомлення.
        :param public_key: Публічний ключ.
        :return: True, якщо підпис вірний, False - інакше.
        """
        p, q, g, y = public_key
        r, s = signature
        if r < 1 or r > q - 1 or s < 1 or s > q - 1:
            return False
        h = int(hashlib.sha256(message.encode()).hexdigest(), 16)
        w = self.mod_inv(s, q)
        u1 = (h * w) % q
        u2 = (r * w) % q
        v = (pow(g, u1, p) * pow(y, u2, p)) % p % q
        return v == r

    def generate_keys(self):
        """
        Генерує приватний і публічний ключі.
        :return: Кортеж, що містить приватний ключ (p, q, g, y, x) і публічний ключ (p, q, g, y).
        """
        q = self.generate_prime(256)
        p = 2 * q + 1
        while not isprime(p):
            q = self.generate_prime(256)
            p = 2 * q + 1

        g = random.randint(2, p - 1)
        x = random.randint(2, q - 1)
        y = pow(g, x, p)

        return (p, q, g, y, x)

text = "Hello Cryptology!"

NR = NybergRueppel()

key_private = NR.generate_keys()
key_public = key_private[:-1]

signature_by_private_key = NR.sign(text, key_private)

print("Text:", text)
print("Key public:", key_public)

print("Signature by private key:", signature_by_private_key)
print("Verification old-message:", NR.check(text, signature_by_private_key, key_public))


new_text = "New text message"
print("New message: ", new_text)
print("Verification new-message:", NR.check(new_text, signature_by_private_key, key_public))
