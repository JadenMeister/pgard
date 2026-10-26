<!-- corpus: expect=low -->
<template>
  <div v-html="safeHtml"></div>
</template>
<script>
import sanitizeHtml from "sanitize-html";
export default {
  props: { html: String },
  computed: {
    safeHtml() {
      return sanitizeHtml(this.html);
    },
  },
};
</script>
