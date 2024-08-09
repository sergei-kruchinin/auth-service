from auths import app, db
from auths.routes import *

import os


if __name__ == '__main__':

    # EXPIRES_SECONDS = int(os.getenv('EXPIRES_SECONDS'))
    # print(EXPIRES_SECONDS)
    app.run(debug=True)
