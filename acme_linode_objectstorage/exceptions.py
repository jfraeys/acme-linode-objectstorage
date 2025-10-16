class BucketNotFoundError(Exception):
    """Exception raised when a bucket is not found."""

    def __init__(self, bucket_name):
        self.bucket_name = bucket_name
        super().__init__(f"Bucket '{bucket_name}' not found.")


class BucketAccessError(Exception):
    """Exception raised when an error occurs accessing a bucket."""

    def __init__(self, bucket_name, status_code):
        self.bucket_name = bucket_name
        self.status_code = status_code
        super().__init__(f"Error accessing bucket '{bucket_name}': Status code {status_code}")
