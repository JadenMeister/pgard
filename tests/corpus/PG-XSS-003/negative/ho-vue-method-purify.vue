<!-- corpus: expect=low -->
<template>
  <div v-html="purify(html)"></div>
</template>
<script>
export default {
  props: { html: String },
  methods: {
    purify(value) {
      return value;
    },
  },
};
</script>
