import os
import json
import logging

logger = logging.getLogger(__name__)

SCAN_RESULTS_FOLDER = os.getenv('SCAN_RESULTS_FOLDER', '/tmp/scan-results')
REVIEW_FILE_PATH = os.path.join(SCAN_RESULTS_FOLDER, 'review.json')

# Ensure the review file exists
if not os.path.exists(REVIEW_FILE_PATH):
    with open(REVIEW_FILE_PATH, 'w') as file:
        json.dump([], file)  # Initialize as an empty list

def get_review_data():
    """Retrieve the list of scan results marked for review."""
    try:
        with open(REVIEW_FILE_PATH, 'r') as file:
            return json.load(file)
    except Exception as e:
        logger.error(f"Failed to load review data: {e}")
        return []

def add_review_entry(scan_type, path):
    """Log virus detection for manual review."""
    review_entry = {
        'scan_type': scan_type,
        'path': path,
        'status': 'Pending Review'
    }
    try:
        with open(REVIEW_FILE_PATH, 'r+') as file:
            data = json.load(file)
            data.append(review_entry)
            file.seek(0)
            json.dump(data, file, indent=4)
        logger.info(f"Review entry added for {path}.")
    except Exception as e:
        logger.error(f"Failed to update review log: {e}")

def mark_review_item_reviewed(index):
    """Mark a review item as reviewed."""
    try:
        with open(REVIEW_FILE_PATH, 'r+') as file:
            data = json.load(file)
            data[index]['status'] = 'Reviewed'
            file.seek(0)
            json.dump(data, file, indent=4)
        return True, "Item marked as reviewed."
    except Exception as e:
        logger.error(f"Failed to mark as reviewed: {e}")
        return False, str(e)

def delete_review_item(index):
    """Delete a review item."""
    try:
        with open(REVIEW_FILE_PATH, 'r+') as file:
            data = json.load(file)
            data.pop(index)
            file.seek(0)
            file.truncate()  # Remove remaining old data
            json.dump(data, file, indent=4)
        return True, "Item deleted."
    except Exception as e:
        logger.error(f"Failed to delete review: {e}")
        return False, str(e)
