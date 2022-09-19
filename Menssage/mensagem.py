from  __future__ import absolute_import, division, print_function

from cryptography.hazmat import backends

class Mensage_Realtime():
    def message(self, key, backend):
        if backend is None:
            backend = default_backend()
            print('Mensagem Real time incompativel')
        key = base64.urlsafe_b64decode(key)
        if len(key) != 32:
            raise ValueError(
                "Fernet key must be 32 url-safe base64-encoded bytes."
            )
        else:  {
  "M": "Sety,865210037139119,0,82,4059,1,724,05,0520,4e51,03,20,724,05,0520,4ea6,27,13,724,05,0520,4e55,14,10"
        }
        print('Mensagem Real Time encaminhada para o banco de dados com sucesso')

class Menssage_B():
    def message(self, key, backend):
        if backend is None:
            backend = default_backend()
            print('Mensagem Bath incompativel')
        key = base64.urlsafe_b64decode(key)
        if len(key) != 32:
            raise ValueError(
                "Fernet key must be 32 url-safe base64-encoded bytes."
            )
        else: {
            "B": "Sety,865210037139119,1,81,4054,1,724,05,0520,4ea6,27,19,,,,,,,,,,,,,"
        }
        print('Mensagem Bath encaminhada para o banco de dados com sucesso')
