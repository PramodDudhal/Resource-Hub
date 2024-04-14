import os
from datetime import datetime
from shutil import copyfile
from app import create_app, db
from app import Resource

def populate_resources_from_folder(directory_path, upload_folder):
    """
    Populate the Resource table with PDF files from subject-wise folders in the specified directory.

    Args:
        directory_path (str): Path to the root directory containing subject-wise folders.
        upload_folder (str): Path to the upload folder where files will be copied.
    """
    username = 'Admin'  # Username for all resources

    # Iterate over each subject folder in the specified directory
    for subject_folder in os.listdir(directory_path):
        subject_folder_path = os.path.join(directory_path, subject_folder)

        if not os.path.isdir(subject_folder_path):
            continue

        # Iterate over each file (PDF) in the subject folder
        for filename in os.listdir(subject_folder_path):
            file_path = os.path.join(subject_folder_path, filename)

            if not os.path.isfile(file_path) or not filename.lower().endswith('.pdf'):
                continue

            # Extract file metadata
            title = filename[:-4]  # Remove file extension for title
            upload_date = datetime.now()  # Today's date

            # Create a new Resource object and add to the database session
            new_resource = Resource(
                user_username=username,
                year_of_studying='1st Year',
                branch_of_study='computer',
                subject=subject_folder,
                resource_type='Past Year Paper',
                title=title,
                file_path=file_path,
                upload_date=upload_date
            )

            db.session.add(new_resource)
            # Copy the file to the upload folder
            destination_path = os.path.join(upload_folder, filename)
            copyfile(file_path, destination_path)

    # Commit all changes to the database
    db.session.commit()

if __name__ == '__main__':
    # Create the Flask application
    app = create_app()

    # Specify the directory path containing subject-wise folders
    directory_path = '/home/pramod/Documents/Main_Folder1'

    # Specify the upload folder path
    upload_folder = '/home/pramod/Documents/SEM IV/RPPOOP/final/Resource-Hub/uploads'

    # Use application context to interact with the database
    with app.app_context():
        # Populate resources from the specified directory
        populate_resources_from_folder(directory_path, upload_folder)
