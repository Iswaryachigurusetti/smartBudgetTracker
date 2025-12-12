# Use a lightweight Nginx image
FROM nginx:alpine

# Copy the frontend files to the Nginx HTML directory
COPY index.html /usr/share/nginx/html/
EXPOSE 80
# Nginx will serve the index.html file on port 80 inside the container
CMD ["nginx", "-g", "daemon off;"]