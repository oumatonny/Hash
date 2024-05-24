import streamlit as st
import hashlib
import itertools
import time

class PasswordUtil:
    def __init__(self):
        self.alphabet = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ'
        self.max_password_length = 8  

    def hash_generator(self, plain_text, salt_value):
        combined = plain_text + salt_value
        hashed_value = hashlib.sha256(combined.encode()).hexdigest()
        return hashed_value

    def test_case_creator(self, plain_text, salt_value):
        hashed_value = self.hash_generator(plain_text, salt_value)
        with open("test_case.txt", "w") as file_writer:
            file_writer.write(f"Password: {plain_text}\n")
            file_writer.write(f"Hashed Value: {hashed_value}\n")
        return hashed_value

    def password_recover(self, hashed_value, salt_value):
        for password_length in range(1, self.max_password_length + 1):
            password_combinations = itertools.product(self.alphabet, repeat=password_length)
            for password_attempt in password_combinations:
                password_attempt = ''.join(password_attempt)
                if self.hash_generator(password_attempt, salt_value) == hashed_value:
                    return password_attempt
        return None

    def time_test_case_creator(self, plain_text, salt_value):
        start_time = time.time()
        hashed_value = self.test_case_creator(plain_text, salt_value)
        end_time = time.time()
        return end_time - start_time, hashed_value

    def time_password_recover(self, hashed_value, salt_value):
        start_time = time.time()
        recovered_password = self.password_recover(hashed_value, salt_value)
        end_time = time.time()
        return end_time - start_time, recovered_password

def main():
    st.title("Password Recovery Program")
    password_util = PasswordUtil()

    option = st.sidebar.selectbox("Select an option", ["Create test case", "Recover password"])

    if option == "Create test case":
        plain_text = st.text_input("Enter the password")
        salt_value = st.text_input("Enter the salt value")

        if st.button("Create Test Case"):
            time_taken, hashed_value = password_util.time_test_case_creator(plain_text, salt_value)
            st.success(f"Hashed value generated and saved. Time taken: {time_taken:.6f} seconds")
            st.code(f"Password: {plain_text}\nHashed Value: {hashed_value}")

    elif option == "Recover password":
        salt_value = st.text_input("Enter the salt value")
        hashed_value = st.text_input("Enter the hashed password")

        if st.button("Recover Password"):
            time_taken, recovered_password = password_util.time_password_recover(hashed_value, salt_value)
            if recovered_password:
                st.success(f"Recovered password: {recovered_password}")
            else:
                st.warning("Failed to recover the password.")
            st.info(f"Time taken: {time_taken:.6f} seconds")

if __name__ == "__main__":
    main()