import os
from Backend.vars import uploads_dir


def clear_files(directory: str):
    try:
        for filename in os.listdir(directory):
            file_path = os.path.join(directory, filename)
            if os.path.isfile(file_path):
                os.remove(file_path)
                print(f"Removed file: {file_path}")
            else:
                print(f"Skipped non-file: {file_path}")
    except Exception as e:
        print(f"Error clearing files: {e}")
