const UglifyJsPlugin = require('uglifyjs-webpack-plugin');
const GitRevisionPlugin = require('git-revision-webpack-plugin');
const gitRevisionPlugin = new GitRevisionPlugin({branch: true});
const DefinePlugin = require('webpack').DefinePlugin;

const pkg = require('./package.json');

module.exports = {
  entry: './src/index.js',
  plugins: [
    gitRevisionPlugin,
    new DefinePlugin({
      'VERSION': JSON.stringify(gitRevisionPlugin.version()),
      'COMMITHASH': JSON.stringify(gitRevisionPlugin.commithash()),
      'BRANCH': JSON.stringify(gitRevisionPlugin.branch())
    })
  ],
  output: {
    filename: pkg.name + ".v" + pkg.version + '.[git-revision-version].js'
  },
  module: {
    rules: [
      {
        test: /\.m?js$/,
        exclude: /(node_modules|bower_components)/,
        use: {
          loader: 'babel-loader',
          options: {
            presets: ['@babel/preset-env']
          }
        }
      }
    ]
  }
}