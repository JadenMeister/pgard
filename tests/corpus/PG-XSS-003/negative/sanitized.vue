<!-- corpus: expect=none; known=fp:PG-XSS-003:DOMPurify.sanitize inside a computed property is not followed -->
<template>
  <div v-html="clean"></div>
</template>
<script setup>
import DOMPurify from "dompurify";
import { computed } from "vue";
const props = defineProps({ html: String });
const clean = computed(() => DOMPurify.sanitize(props.html));
</script>
