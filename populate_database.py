# populate_database.py

import os
from datetime import datetime
from app import create_app, db  # Import create_app function to initialize the app
from app import Resource  # Import Resource model from app.models

def populate_resources(directory_path):
    """
    Populate the Resource table with PDF files from subject-wise folders in the specified directory.

    Args:
        directory_path (str): Path to the root directory containing subject-wise folders.

    Returns:
        int: Number of resources added to the database.
    """
    count = 0
    username = 'Admin'  # Username for all resources

    # Create the Flask application instance
    app = create_app()

    # Establish app context to work with the database
    with app.app_context():
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
                upload_date = datetime.today().date()  # Today's date

                # Create a new Resource object and add to the database session
                resource = Resource(
                    title=title,
                    year_of_studying='First year',
                    branch_of_study='Computer Engineering',
                    subject=subject_folder,
                    resource_type='PDF',
                    file_path=file_path,
                    upload_date=upload_date,
                    user_username=username
                )

                db.session.add(resource)
                count += 1

        # Commit all changes to the database
        db.session.commit()

    return count

if __name__ == '__main__':
    # Specify the directory path where subject-wise folders are located
    directory_path = '/home/pramod/Documents/Main_Folder'  # Update with the actual path to your subject folders
    
    # Populate the database with resources from the specified directory
    num_resources_added = populate_resources(directory_path)
    
    print(f"Added {num_resources_added} resources to the database.")
