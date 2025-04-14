module.exports = {
  root: true,
  env: {
    node: true
  },
  extends: [
    'plugin:vue/essential',
    'eslint:recommended'
  ],
  parserOptions: {
    parser: 'babel-eslint'
  },
  rules: {
    'no-console': 'off',
    'no-debugger': 'off',
    'vue/no-unused-components': 'off',
    'no-unused-vars': 'off',
    'vue/multi-word-component-names': 'off',
    'no-prototype-builtins': 'off'
  }
}
