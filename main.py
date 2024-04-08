#main.py

from flask import Flask, request, render_template_string, render_template
import base64
from BabyAES import aes_instance

app = Flask(__name__)

def str_to_bytes(s):
    return [ord(c) for c in s]

def bytes_to_str(byte_array):
    return ''.join(chr(byte) for byte in byte_array)

def pad(byte_array, block_size=16):
    padding_needed = block_size - (len(byte_array) % block_size)
    # Padding starts with '80' (in hex) followed by zero bytes
    return byte_array + b'\x80' + b'\x00' * (padding_needed - 1)

def unpad(byte_array, block_size=16):
    # Find the last non-zero byte (which should be '80' in hex)
    padding_start = byte_array.rfind(b'\x80')
    if padding_start == -1:
        raise ValueError("Padding not found")
    return byte_array[:padding_start]


@app.route('/')
def index():
    return render_template('index.html')

@app.route('/encrypt', methods=['GET', 'POST'])
def encrypt_endpoint():
    steps = None
    plaintext = ""  # Initialize plaintext to an empty string
    if request.method == 'POST':
        plaintext = request.form['plaintext']
        plaintext_bytes = plaintext.encode('utf-8')
        padded_plaintext_bytes = pad(plaintext_bytes)
        steps = aes_instance.encrypt(padded_plaintext_bytes)
        # Convert each step to base64 for displaying
        for i in range(len(steps)):
            step_name, step_data = steps[i]
            steps[i] = (step_name, base64.b64encode(step_data).decode('utf-8'))
    return render_template('encrypt.html', plaintext=plaintext, steps=steps)

@app.route('/decrypt', methods=['GET', 'POST'])
def decrypt_endpoint():
    steps = None
    decrypted_text = None  # Initialize decrypted_text
    b64_ciphertext = None
    if request.method == 'POST':
        b64_ciphertext = request.form['ciphertext']
        ciphertext_bytes = base64.b64decode(b64_ciphertext)
        steps = aes_instance.decrypt(ciphertext_bytes)
        # The last step should give you the final state, unpad it to get the plaintext
        final_state = steps[-1][1]  # This should be the byte array after final AddRoundKey
        try:
            unpadded = unpad(final_state)  # Attempt to unpad
            decrypted_text = bytes_to_str(unpadded)  # Convert bytes to string
        except ValueError as e:
            decrypted_text = f"Decryption failed: {str(e)}"
            steps = []  # Clear the steps to indicate an error occurred
        # Convert each step to base64 for displaying
        for i in range(len(steps)):
            step_name, step_data = steps[i]
            steps[i] = (step_name, base64.b64encode(step_data).decode('utf-8'))

    return render_template('decrypt.html', decrypted_text=decrypted_text, b64_ciphertext=b64_ciphertext, steps=steps)

@app.route('/finite-fields')
def finite_fields():
    return render_template('finite-fields.html')

@app.route('/spn')
def spn():
    return render_template('spn.html')

@app.route('/s-box')
def sub():
    return render_template('s-box.html')

@app.route('/xor')
def xor():
    return render_template('xor.html')

@app.route('/key-schedule')
def keyschedule():
    return render_template('key-schedule.html')

@app.route('/shiftrows-mixcolumns')
def shiftrowsmixcolumns():
    return render_template('shiftrows-mixcolumns.html')

@app.route('/matrix-operations')
def matrixoperations():
    return render_template('matrix-operations.html')

@app.route('/cyclic-groups')
def cyclicgroups():
    return render_template('cyclic-groups.html')

@app.route('/aes-history')
def aeshistory():
    return render_template('aes-history.html')

@app.route('/aes-working')
def aesalgorithm():
    return render_template('aes-working.html')

if __name__ == '__main__':
    app.run(debug=True)
