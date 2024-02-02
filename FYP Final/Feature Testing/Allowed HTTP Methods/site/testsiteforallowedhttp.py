from flask import Flask, jsonify, request, render_template

app = Flask(__name__)

# Sample data
data = {"message": "Hello, this is a sample API!", "items": []}

# GET request endpoint
@app.route('/api/hello', methods=['GET'])
def hello():
    return jsonify(data)

# POST request endpoint
@app.route('/api/items', methods=['POST'])
def add_item():
    # if request.is_json:
    #     content = request.get_json()
    #     item = content.get('item', '')
    #     data['items'].append(item)
    #     return jsonify({"message": "Item added successfully"})
    # else:
    #     return jsonify({"error": "Invalid request, must be a JSON POST request"}), 400
    return jsonify({"message": "Item added successfully"})

# PUT request endpoint
@app.route('/api/items', methods=['PUT'])
def update_item(item_id):
    # if request.is_json:
    #     content = request.get_json()
    #     new_item = content.get('item', '')
    #     if 0 <= item_id < len(data['items']):
    #         data['items'][item_id] = new_item
    #         return jsonify({"message": "Item updated successfully"})
    #     else:
    #         return jsonify({"error": "Item not found"}), 404
    # else:
    #     return jsonify({"error": "Invalid request, must be a JSON PUT request"}), 400
    return jsonify({"message": "Item updated successfully"})

# DELETE request endpoint
@app.route('/api/items', methods=['DELETE'])
def delete_item(item_id):
    # if 0 <= item_id < len(data['items']):
    #     del data['items'][item_id]
    #     return jsonify({"message": "Item deleted successfully"})
    # else:
    #     return jsonify({"error": "Item not found"}), 404
    return jsonify({"message": "Item added successfully"})

# OPTIONS request endpoint
@app.route('/api/options', methods=['OPTIONS'])
def options():
    return jsonify({"message": "Options request successful"})

# PATCH request endpoint
@app.route('/api/items', methods=['PATCH'])
def patch_item(item_id):
    # if request.is_json:
    #     content = request.get_json()
    #     updated_fields = content.get('updated_fields', {})
    #     if 0 <= item_id < len(data['items']):
    #         for key, value in updated_fields.items():
    #             data['items'][item_id][key] = value
    #         return jsonify({"message": "Item patched successfully"})
    #     else:
    #         return jsonify({"error": "Item not found"}), 404
    # else:
    #     return jsonify({"error": "Invalid request, must be a JSON PATCH request"}), 400
    return jsonify({"message": "Item added successfully"})

# HTML form for the POST request
# HTML form for the PUT request
@app.route('/', methods=['GET'])
def form_index():
    return render_template('form_get.html')

@app.route('/form_get', methods=['GET'])
def form_index2():
    return render_template('form_get.html')

@app.route('/form_post', methods=['GET'])
def form_post():
    return render_template('form_post.html')

# HTML form for the PUT request
@app.route('/form_put', methods=['GET'])
def form_put():
    return render_template('form_put.html')

# HTML form for the DELETE request
@app.route('/form_delete', methods=['GET'])
def form_delete():
    return render_template('form_delete.html')

# HTML form for the PATCH request
@app.route('/form_patch', methods=['GET'])
def form_patch():
    return render_template('form_patch.html')

if __name__ == '__main__':
    # Run the application on http://127.0.0.1:5000/
    app.run(debug=True)