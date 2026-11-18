<!-- corpus: expect=none -->
<template>
  <div v-html="DOMPurify.sanitize(html, purifyOptions)"></div>
</template>
<script setup>
import DOMPurify from "dompurify";
defineProps({ html: String });
const purifyOptions = { ADD_ATTR: ["target"] };
</script>
