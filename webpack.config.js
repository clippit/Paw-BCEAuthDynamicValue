const path = require('path');

const name = 'BCEAuthDynamicValue';

module.exports = {
    entry: [
        `./src/${name}.js`
    ],
    output: {
        filename: `${name}.js`,
        path: path.resolve(__dirname, 'build', `com.baidu.PawExtensions.${name}`)
    },
    mode: "none",
    module: {
        rules: [
            {
                test: /\.js$/,
                exclude: /(node_modules|bower_components)/,
                use: {
                    loader: 'babel-loader',
                    options: {
                        presets: [
                            ['@babel/preset-env', {
                                targets: {
                                    browsers: ['safari >= 7']
                                }
                            }]
                        ]
                    }
                }
            }
        ]
    }
};