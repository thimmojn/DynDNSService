#!/usr/bin/env python3
# -*- encoding: utf-8-unix -*-

from passlib.hash import argon2


def main():
    password = input()
    pwdHash = argon2.hash(password)
    print('Passwort:', password)
    print('Hash:', pwdHash)


if __name__ == '__main__':
    main()
