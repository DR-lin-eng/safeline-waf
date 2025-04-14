rules: {
    'no-console': process.env.NODE_ENV === 'production' ? 'warn' : 'off',
    'no-debugger': process.env.NODE_ENV === 'production' ? 'warn' : 'off',
    // 放宽一些规则，以便于开发
    'vue/no-unused-components': 'warn',
    'no-unused-vars': 'warn',
    // 禁用多词组件名称规则
    'vue/multi-word-component-names': 'off',
    // 禁用hasOwnProperty直接调用规则
    'no-prototype-builtins': 'off'
  }
